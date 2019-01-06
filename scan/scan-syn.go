package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/mostlygeek/arp"
	"github.com/phayes/freeport"
	"github.com/sirupsen/logrus"
)

type portJob struct {
	ip       net.IP
	port     int
	open     chan int
	closed   chan int
	filtered chan int
	done     chan struct{}
	ctx      context.Context
}

type hostJob struct {
	ip         net.IP
	ports      []int
	resultChan chan *Result
	done       chan struct{}
	ctx        context.Context
}

type SynScanner struct {
	timeout          time.Duration
	maxRoutines      int
	jobChan          chan hostJob
	ti               *TargetIterator
	serializeOptions gopacket.SerializeOptions
}

func NewSynScanner(ti *TargetIterator, timeout time.Duration, paralellism int) *SynScanner {

	return &SynScanner{
		serializeOptions: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		timeout:     timeout,
		maxRoutines: paralellism,
		jobChan:     make(chan hostJob, paralellism),
		ti:          ti,
	}
}

func (s *SynScanner) Stop() {

}

func (s *SynScanner) Start() error {

	for i := 0; i < s.maxRoutines; i++ {
		go func() {
			for {
				job := <-s.jobChan
				if job.ports == nil || len(job.ports) == 0 {
					break
				}
				result, err := s.scanHost(job)
				if err != nil {
					logrus.Debugf("Error scanning host %s: %s", job.ip, err)
					// @todo handle this?
				}
				job.resultChan <- &result
				close(job.done)
			}
		}()
	}

	return nil
}

func (s *SynScanner) getHwAddr(ip net.IP, gateway net.IP, srcIP net.IP, networkInterface *net.Interface) (net.HardwareAddr, error) {

	// grab mac from ARP table if we have it cached
	macStr := arp.Search(ip.String())
	if macStr != "00:00:00:00:00:00" {
		if mac, err := net.ParseMAC(macStr); err == nil {
			return mac, nil
		}
	}

	arpDst := ip
	if gateway != nil {
		arpDst = gateway
	}

	handle, err := pcap.OpenLive(networkInterface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	start := time.Now()

	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       networkInterface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(networkInterface.HardwareAddr),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}

	buf := gopacket.NewSerializeBuffer()

	// Send a single ARP request packet (we never retry a send, since this
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, &eth, &arp); err != nil {
		return nil, err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > s.timeout {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(arpDst) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

// send sends the given layers as a single packet on the network.
func (s *SynScanner) send(handle *pcap.Handle, l ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

func (s *SynScanner) Scan(ctx context.Context, ports []int) ([]Result, error) {

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

		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		tIP := make([]byte, len(ip))
		copy(tIP, ip)
		go func(host net.IP, ports []int, wg *sync.WaitGroup) {

			done := make(chan struct{})

			s.jobChan <- hostJob{
				resultChan: resultChan,
				ip:         host,
				ports:      ports,
				done:       done,
				ctx:        ctx,
			}

			<-done
			wg.Done()
		}(tIP, ports, wg)
	}

	wg.Wait()
	close(s.jobChan)
	close(resultChan)
	<-doneChan

	s.Stop()

	return results, nil
}

func (s *SynScanner) scanHost(job hostJob) (Result, error) {

	result := NewResult(job.ip)

	select {
	case <-job.ctx.Done():
		return result, nil
	default:
	}

	router, err := routing.New()
	if err != nil {
		return result, err
	}
	networkInterface, gateway, srcIP, err := router.Route(job.ip)
	if err != nil {
		return result, err
	}

	handle, err := pcap.OpenLive(networkInterface.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return result, err
	}
	defer handle.Close()

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
				for _, existing := range result.Open {
					if existing == open {
						continue
					}
				}
				result.Open = append(result.Open, open)
			case closed := <-closedChan:
				if result.Latency < 0 {
					result.Latency = time.Since(startTime)
				}
				for _, existing := range result.Closed {
					if existing == closed {
						continue
					}
				}
				result.Closed = append(result.Closed, closed)
			case filtered := <-filteredChan:
				if result.Latency < 0 {
					result.Latency = time.Since(startTime)
				}
				for _, existing := range result.Filtered {
					if existing == filtered {
						continue
					}
				}
				result.Filtered = append(result.Filtered, filtered)
			}
		}
	}()

	rawPort, err := freeport.GetFreePort()
	if err != nil {
		return result, err
	}

	// First off, get the MAC address we should be sending packets to.
	hwaddr, err := s.getHwAddr(job.ip, gateway, srcIP, networkInterface)
	if err != nil {
		return result, err
	}

	// Construct all the network layers we need.
	eth := layers.Ethernet{
		SrcMAC:       networkInterface.HardwareAddr,
		DstMAC:       hwaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    job.ip,
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rawPort),
		DstPort: 0,
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	listenChan := make(chan struct{})

	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, job.ip, srcIP)

	go func() {

		eth := &layers.Ethernet{}
		ip4 := &layers.IPv4{}
		tcp := &layers.TCP{}

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, eth, ip4, tcp)

		for {

			select {
			case <-job.ctx.Done():
				break
			default:
			}

			// Read in the next packet.
			data, _, err := handle.ReadPacketData()
			if err == pcap.NextErrorTimeoutExpired {
				break
			} else if err == io.EOF {
				break
			} else if err != nil {
				// connection closed
				fmt.Printf("Packet read error: %s\n", err)
				continue
			}

			decoded := []gopacket.LayerType{}
			if err := parser.DecodeLayers(data, &decoded); err != nil {
				continue
			}
			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeIPv4:
					if ip4.NetworkFlow() != ipFlow {
						continue
					}
				case layers.LayerTypeTCP:
					if tcp.DstPort != layers.TCPPort(rawPort) {
						continue
					} else if tcp.SYN && tcp.ACK {
						openChan <- int(tcp.SrcPort)
					} else if tcp.RST {
						closedChan <- int(tcp.SrcPort)
					}
				}
			}

		}

		close(listenChan)

	}()

	for _, port := range job.ports {
		tcp.DstPort = layers.TCPPort(port)
		_ = s.send(handle, &eth, &ip4, &tcp)
	}

	timer := time.AfterFunc(s.timeout, func() { handle.Close() })
	defer timer.Stop()

	<-listenChan

	close(openChan)
	<-doneChan

	return result, nil
}

func (s *SynScanner) OutputResult(result Result) {
	fmt.Println(result.String())
}
