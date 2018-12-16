package main

import (
	"fmt"
	"github.com/mostlygeek/arp"
)

func main() {
	for ip, _ := range arp.Table() {
		fmt.Printf("%s : %s\n", ip, arp.Search(ip))
	}
}
