package scan

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/macs"
	"github.com/mostlygeek/arp"
)

type DeviceScanner struct {
	timeout time.Duration
	ti      *TargetIterator
}

func NewDeviceScanner(ti *TargetIterator, timeout time.Duration) *DeviceScanner {
	return &DeviceScanner{
		timeout: timeout,
		ti:      ti,
	}
}

func (s *DeviceScanner) Start() error {

	return nil
}

func (s *DeviceScanner) Stop() {

}

func (s *DeviceScanner) Scan(ctx context.Context, ports []int) ([]Result, error) {

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
		go func(ip net.IP, wg *sync.WaitGroup) {
			r := NewResult(ip)

			select {
			case <-ctx.Done():
				wg.Done()
				return
			default:
			}

			macStr := arp.Search(ip.String())

			if macStr != "00:00:00:00:00:00" {

				if mac, err := net.ParseMAC(macStr); err == nil {

					r.MAC = mac.String()

					prefix := [3]byte{
						mac[0],
						mac[1],
						mac[2],
					}

					manufacturer, ok := macs.ValidMACPrefixMap[prefix]
					if ok {
						r.Manufacturer = manufacturer
					}

					// only bother looking up hostname for local devices
					if addr, err := net.LookupAddr(ip.String()); err == nil && len(addr) > 0 {
						r.Name = addr[0]
					}

				}
			}

			start := time.Now()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:1", ip.String()), s.timeout)
			if err != nil {
				if !strings.Contains(err.Error(), "timeout") {
					r.Latency = time.Since(start)
				}
			} else {
				r.Latency = time.Since(start)
				conn.Close()
			}

			select {
			case <-ctx.Done():
			case resultChan <- &r:
			}

			wg.Done()
		}(tIP, wg)

		_ = ip
	}

	wg.Wait()
	close(resultChan)
	<-doneChan

	return results, nil
}

func (s *DeviceScanner) OutputResult(result Result) {

	fmt.Printf("Scan results for host %s\n", result.Host.String())

	status := "DOWN"

	if result.IsHostUp() {
		status = "UP"
	}

	fmt.Printf(
		"\t%s %s\n",
		pad("Status:", 24),
		status,
	)

	if result.IsHostUp() {
		fmt.Printf(
			"\t%s %s\n",
			pad("Latency:", 24),
			result.Latency.String(),
		)
	}

	if result.MAC != "" {
		fmt.Printf(
			"\t%s %s\n",
			pad("MAC:", 24),
			result.MAC,
		)
	}

	if result.Manufacturer != "" {
		fmt.Printf(
			"\t%s %s\n",
			pad("Manufacturer:", 24),
			result.Manufacturer,
		)
	}

	if result.Name != "" {
		fmt.Printf(
			"\t%s %s\n",
			pad("Name:", 24),
			result.Name,
		)
	}

	fmt.Println("")
}
