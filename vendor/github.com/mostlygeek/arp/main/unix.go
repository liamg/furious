package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func main() {
	data, err := exec.Command("arp", "-an").Output()
	if err != nil {
		panic(err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// strip brackets around IP
		ip := strings.Replace(fields[1], "(", "", -1)
		ip = strings.Replace(ip, ")", "", -1)

		mac := fields[3]
		fmt.Println(ip, mac)
	}

}
