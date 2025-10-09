package scan

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type ConnectScanner struct {
	timeout     time.Duration
	maxRoutines int
	jobChan     chan portJob
	ti          *TargetIterator
}

func NewConnectScanner(ti *TargetIterator, timeout time.Duration, paralellism int) *ConnectScanner {
	return &ConnectScanner{
		timeout:     timeout,
		maxRoutines: paralellism,
		jobChan:     make(chan portJob, paralellism),
		ti:          ti,
	}
}

func (s *ConnectScanner) Start() error {

	for i := 0; i < s.maxRoutines; i++ {
		go func() {
			for {
				job := <-s.jobChan
				if job.port == 0 {
					break
				}

				select {
				case <-job.ctx.Done():
					close(job.done)
					return
				default:
				}

				if state, err := s.scanPort(job.ip, job.port); err == nil {
					switch state {
					case PortOpen:
						job.open <- job.port
					case PortClosed:
						job.closed <- job.port
					case PortFiltered:
						job.filtered <- job.port
					}
				}
				close(job.done)
			}
		}()
	}

	return nil
}

func (s *ConnectScanner) Stop() {

}

func (s *ConnectScanner) Scan(ctx context.Context, ports []int) ([]Result, error) {

	wg := &sync.WaitGroup{}

	resultChan := make(chan *Result)
	results := []Result{}
	doneChan := make(chan struct{})

	go func() {
		for {
			result := <-resultChan
			if result == nil {
				close(doneChan)
				break
			}
			results = append(results, *result)
		}
	}()

	for {
		ip, err := s.ti.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		wg.Add(1)
		tIP := make([]byte, len(ip))
		copy(tIP, ip)
		go func(ip net.IP, ports []int, wg *sync.WaitGroup) {
			r := s.scanHost(ctx, ip, ports)
			resultChan <- &r
			wg.Done()
		}(tIP, ports, wg)

		_ = ip
	}

	wg.Wait()
	close(resultChan)
	close(s.jobChan)
	<-doneChan

	return results, nil
}

func (s *ConnectScanner) scanHost(ctx context.Context, host net.IP, ports []int) Result {

	wg := &sync.WaitGroup{}

	result := NewResult(host)

	openChan := make(chan int, len(ports))
	closedChan := make(chan int, len(ports))
	filteredChan := make(chan int, len(ports))
	doneChan := make(chan struct{})

	startTime := time.Now()
	var latencySet bool
	var mu sync.Mutex

	go func() {
		portsProcessed := 0
		totalPorts := len(ports)
		
		for portsProcessed < totalPorts {
			select {
			case open := <-openChan:
				mu.Lock()
				if !latencySet {
					result.Latency = time.Since(startTime)
					latencySet = true
				}
				result.Open = append(result.Open, open)
				portsProcessed++
				mu.Unlock()
			case closed := <-closedChan:
				mu.Lock()
				if !latencySet {
					result.Latency = time.Since(startTime)
					latencySet = true
				}
				result.Closed = append(result.Closed, closed)
				portsProcessed++
				mu.Unlock()
			case filtered := <-filteredChan:
				mu.Lock()
				if !latencySet {
					result.Latency = time.Since(startTime)
					latencySet = true
				}
				result.Filtered = append(result.Filtered, filtered)
				portsProcessed++
				mu.Unlock()
			case <-ctx.Done():
				close(doneChan)
				return
			}
		}
		close(doneChan)
	}()

	for _, port := range ports {
		wg.Add(1)
		go func(p int, wg *sync.WaitGroup) {
			defer wg.Done()

			done := make(chan struct{})

			s.jobChan <- portJob{
				open:     openChan,
				closed:   closedChan,
				filtered: filteredChan,
				ip:       host,
				port:     p,
				done:     done,
				ctx:      ctx,
			}

			<-done

		}(port, wg)
	}

	wg.Wait()
	<-doneChan

	return result
}

func (s *ConnectScanner) scanPort(target net.IP, port int) (PortState, error) {

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.String(), port), s.timeout)
	if err != nil {
		// Connection refused means the host is up but port is closed
		if strings.Contains(err.Error(), "refused") || 
		   strings.Contains(err.Error(), "connection refused") {
			return PortClosed, nil
		}
		// Connection reset also means host is up but port is closed/filtered
		if strings.Contains(err.Error(), "reset") ||
		   strings.Contains(err.Error(), "connection reset") {
			return PortClosed, nil
		}
		// Timeout or no route means filtered or host down
		if strings.Contains(err.Error(), "timeout") ||
		   strings.Contains(err.Error(), "no route") ||
		   strings.Contains(err.Error(), "network is unreachable") {
			return PortFiltered, nil
		}
		// Other errors (like "no such host") indicate the host is down
		return PortUnknown, err
	}
	conn.Close()
	return PortOpen, nil
}

func (s *ConnectScanner) OutputResult(result Result) {
	fmt.Println(result.String())
}
