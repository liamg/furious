// +build darwin

package scan

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/route"
)

type darwinRouter struct{}

func newDarwinRouter() (Router, error) {
	return &darwinRouter{}, nil
}

func (r *darwinRouter) Route(dst net.IP) (iface *net.Interface, gateway net.IP, src net.IP, err error) {
	// Get routing table
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to fetch routing table: %v", err)
	}

	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse routing table: %v", err)
	}

	var bestRoute *route.RouteMessage
	var bestMask net.IPMask
	
	// Find the most specific route for the destination
	for _, msg := range msgs {
		if rm, ok := msg.(*route.RouteMessage); ok {
			if rm.Addrs == nil {
				continue
			}
			
			// Get destination and netmask from route
			var routeDst net.IP
			var routeMask net.IPMask
			
			if dst4 := rm.Addrs[syscall.RTAX_DST]; dst4 != nil {
				if inet, ok := dst4.(*route.Inet4Addr); ok {
					routeDst = net.IPv4(inet.IP[0], inet.IP[1], inet.IP[2], inet.IP[3])
				}
			}
			
			if mask := rm.Addrs[syscall.RTAX_NETMASK]; mask != nil {
				if inet, ok := mask.(*route.Inet4Addr); ok {
					routeMask = net.IPv4Mask(inet.IP[0], inet.IP[1], inet.IP[2], inet.IP[3])
				}
			}
			
			// Check if this route matches our destination
			if routeDst != nil && routeMask != nil {
				network := routeDst.Mask(routeMask)
				if network.Equal(dst.Mask(routeMask)) {
					// This route matches, check if it's more specific than current best
					if bestRoute == nil || moreSpecific(routeMask, bestMask) {
						bestRoute = rm
						bestMask = routeMask
					}
				}
			} else if routeDst == nil && routeMask == nil {
				// Default route (0.0.0.0/0)
				if bestRoute == nil {
					bestRoute = rm
					bestMask = net.IPv4Mask(0, 0, 0, 0)
				}
			}
		}
	}

	if bestRoute == nil {
		return nil, nil, nil, fmt.Errorf("no route found for %s", dst.String())
	}

	// Extract interface index
	ifaceIndex := bestRoute.Index
	if ifaceIndex == 0 {
		return nil, nil, nil, fmt.Errorf("no interface found for route to %s", dst.String())
	}

	// Get interface by index
	iface, err = net.InterfaceByIndex(ifaceIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get interface by index %d: %v", ifaceIndex, err)
	}

	// Extract gateway if present
	if gw := bestRoute.Addrs[syscall.RTAX_GATEWAY]; gw != nil {
		if inet, ok := gw.(*route.Inet4Addr); ok {
			gateway = net.IPv4(inet.IP[0], inet.IP[1], inet.IP[2], inet.IP[3])
		}
	}

	// Get source IP from interface
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get interface addresses: %v", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			src = ipnet.IP.To4()
			break
		}
	}

	if src == nil {
		return nil, nil, nil, fmt.Errorf("no IPv4 address found on interface %s", iface.Name)
	}

	return iface, gateway, src, nil
}

// moreSpecific returns true if mask1 is more specific than mask2
func moreSpecific(mask1, mask2 net.IPMask) bool {
	ones1, _ := mask1.Size()
	ones2, _ := mask2.Size()
	return ones1 > ones2
}