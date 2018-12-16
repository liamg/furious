package scan

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

type job struct {
	ip       net.IP
	port     int
	open     chan int
	closed   chan int
	filtered chan int
	done     chan struct{}
}

type SynScanner struct {
	conn          net.PacketConn
	stateChannels map[string]chan PortState
	chanLock      sync.RWMutex
	timeout       time.Duration
	maxRoutines   int
	jobChan       chan job
}

func NewSynScanner(timeout time.Duration, paralellism int) *SynScanner {

	return &SynScanner{
		stateChannels: map[string]chan PortState{},
		timeout:       timeout,
		maxRoutines:   paralellism,
		jobChan:       make(chan job, paralellism),
	}
}

func (s *SynScanner) Stop() {
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *SynScanner) Start() error {

	var err error
	s.conn, err = net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return err
	}

	go func() {
		defer s.conn.Close()
		for {
			b := make([]byte, 4096)
			n, addr, err := s.conn.ReadFrom(b)
			if err != nil {
				log.Debugf("Connection read error: %s", err)
				return
			}

			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				key := fmt.Sprintf("%s:%d", addr.String(), tcp.DstPort)

				s.chanLock.RLock()
				c, ok := s.stateChannels[key]
				s.chanLock.RUnlock()
				if !ok {
					continue
				}

				log.Debugf("Received response from %s:%d...", addr.String(), tcp.SrcPort)

				if tcp.SYN && tcp.ACK {
					c <- PortOpen
				} else if tcp.RST {
					c <- PortClosed
				} else {
					c <- PortFiltered
				}
			}

		}
	}()

	for i := 0; i < s.maxRoutines; i++ {
		go func() {
			for {
				job := <-s.jobChan
				if job.port == 0 {
					break
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

func (s *SynScanner) scanPort(target net.IP, port int) (PortState, error) {

	sourceIP, rawPort, err := s.getOutgoingIPWithPort(target)
	if err != nil {
		return PortUnknown, err
	}
	sourcePort := layers.TCPPort(rawPort)

	responseChannel := make(chan PortState)
	s.chanLock.Lock()
	key := fmt.Sprintf("%s:%d", target.String(), rawPort)
	s.stateChannels[key] = responseChannel
	s.chanLock.Unlock()

	// TCP header
	tcp := &layers.TCP{
		SrcPort: sourcePort,
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}
	// set IP header
	tcp.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP:    sourceIP.To4(),
		DstIP:    target.To4(),
		Protocol: layers.IPProtocolTCP,
	})

	// Serialize.  Note:  we only serialize the TCP layer, because the
	// socket we get with net.ListenPacket wraps our data in IPv4 packets
	// already.  We do still need the IP layer to compute checksums
	// correctly, though.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return PortUnknown, err
	}

	s.conn.SetWriteDeadline(time.Now().Add(s.timeout))
	if _, err := s.conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: target}); err != nil {
		return PortUnknown, err
	}

	timer := time.NewTimer(s.timeout)
	defer timer.Stop()

	select {
	case r := <-responseChannel:
		return r, nil
	case <-timer.C:
		return PortUnknown, nil //timed out
	}

}

// get the local ip and port based on our destination ip
func (s *SynScanner) getOutgoingIPWithPort(target net.IP) (net.IP, int, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", target.To4().String()+":12345")
	if err != nil {
		return nil, -1, err
	}

	// We don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.
	con, err := net.DialUDP("udp", nil, serverAddr)
	if err == nil {
		defer con.Close()
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, udpaddr.Port, nil
		} else {
			return nil, -1, fmt.Errorf("Could not determine outgoing address")
		}
	}
	return nil, -1, err
}

func (s *SynScanner) Scan(targetIterator *TargetIterator, ports []int) ([]Result, error) {

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
		ip, err := targetIterator.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		wg.Add(1)
		tIP := make([]byte, len(ip))
		copy(tIP, ip)
		go func(host net.IP, ports []int, wg *sync.WaitGroup) {
			r := s.scanHost(host, ports)
			resultChan <- &r
			wg.Done()
		}(tIP, ports, wg)
	}

	wg.Wait()
	close(resultChan)
	<-doneChan

	s.Stop()

	return results, nil
}

func (s *SynScanner) scanHost(host net.IP, ports []int) Result {

	wg := &sync.WaitGroup{}

	result := NewResult(host)

	openChan := make(chan int)
	closedChan := make(chan int)
	filteredChan := make(chan int)
	doneChan := make(chan struct{})

	startTime := time.Now()

	go func() {
		for {
			select {
			case open := <-openChan:
				if open == 0 {
					close(doneChan)
					return
				}
				if result.Latency < 0 {
					result.Latency = time.Since(startTime)
				}
				result.Open = append(result.Open, open)
			case closed := <-closedChan:
				if result.Latency < 0 {
					result.Latency = time.Since(startTime)
				}
				result.Closed = append(result.Closed, closed)
			case filtered := <-filteredChan:
				if result.Latency < 0 {
					result.Latency = time.Since(startTime)
				}
				result.Filtered = append(result.Filtered, filtered)
			}
		}
	}()

	for _, port := range ports {
		wg.Add(1)
		go func(p int, wg *sync.WaitGroup) {

			done := make(chan struct{})

			s.jobChan <- job{
				open:     openChan,
				closed:   closedChan,
				filtered: filteredChan,
				ip:       host,
				port:     p,
				done:     done,
			}

			<-done
			wg.Done()

		}(port, wg)
	}

	wg.Wait()
	close(openChan)
	<-doneChan

	return result
}

func (s *SynScanner) OutputResult(result Result) {
	fmt.Println(result.String())
}
