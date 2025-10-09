package scan

import (
	"fmt"
	"net"
	"time"
)

type Result struct {
	Host         net.IP
	Open         []int
	Closed       []int
	Filtered     []int
	Manufacturer string
	MAC          string
	Latency      time.Duration
	Name         string
}

func NewResult(host net.IP) Result {
	return Result{
		Host:     host,
		Open:     []int{},
		Closed:   []int{},
		Filtered: []int{},
		Latency:  -1,
	}
}

func (r Result) IsHostUp() bool {
	return r.Latency > -1
}

func (r Result) String() string {

	text := fmt.Sprintf("Scan results for host %s\n", r.Host.String())

	if r.IsHostUp() {
		text = fmt.Sprintf("%s\tHost is up with %s latency\n", text, r.Latency.String())
	} else {
		text = fmt.Sprintf("%s\t%s\n", text, "Host is down")
	}

	if len(r.Open) > 0 {
		text = fmt.Sprintf(
			"%s\t%s\t%s\t%s\n",
			text,
			"PORT",
			"STATE",
			"SERVICE",
		)
	}

	for _, port := range r.Open {
		text = fmt.Sprintf(
			"%s\t%s\t%s\t%s\n",
			text,
			pad(fmt.Sprintf("%d/tcp", port), 10),
			pad("OPEN", 10),
			DescribePort(port),
		)
	}

	return text
}

func pad(input string, length int) string {
	for len(input) < length {
		input += " "
	}
	return input
}
