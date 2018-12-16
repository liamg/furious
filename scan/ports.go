package scan

var DefaultPorts []int

func init() {

	for port := range knownPorts {
		DefaultPorts = append(DefaultPorts, port)
	}
}

func DescribePort(port int) string {
	if s, ok := knownPorts[port]; ok {
		return s
	}

	return ""
}
