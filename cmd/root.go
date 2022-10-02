package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/liamg/furious/scan"
	"github.com/liamg/furious/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var debug bool
var jsonOutput bool
var timeoutMS int = 2000
var parallelism int = 500
var portSelection string
var scanType = "stealth"
var hideUnavailableHosts bool
var versionRequested bool

func init() {
	rootCmd.PersistentFlags().BoolVarP(&hideUnavailableHosts, "up-only", "u", hideUnavailableHosts, "Omit output for hosts which are not up")
	rootCmd.PersistentFlags().BoolVarP(&versionRequested, "version", "", versionRequested, "Output version information and exit")
	rootCmd.PersistentFlags().StringVarP(&scanType, "scan-type", "s", scanType, "Scan type. Must be one of stealth, connect")
	rootCmd.PersistentFlags().BoolVarP(&debug, "verbose", "v", debug, "Enable verbose logging")
	rootCmd.PersistentFlags().BoolVarP(&jsonOutput, "json", "j", jsonOutput, "Enable JSON output")
	rootCmd.PersistentFlags().IntVarP(&timeoutMS, "timeout-ms", "t", timeoutMS, "Scan timeout in MS")
	rootCmd.PersistentFlags().IntVarP(&parallelism, "workers", "w", parallelism, "Parallel routines to scan on")
	rootCmd.PersistentFlags().StringVarP(&portSelection, "ports", "p", portSelection, "Port to scan. Comma separated, can sue hyphens e.g. 22,80,443,8080-8090")
}

func createScanner(ti *scan.TargetIterator, scanTypeStr string, timeout time.Duration, routines int) (scan.Scanner, error) {
	switch strings.ToLower(scanTypeStr) {
	case "stealth", "syn", "fast":
		if os.Geteuid() > 0 {
			return nil, fmt.Errorf("Access Denied: You must be a priviliged user to run this type of scan.")
		}
		return scan.NewSynScanner(ti, timeout, routines), nil
	case "connect":
		return scan.NewConnectScanner(ti, timeout, routines), nil
	case "device":
		return scan.NewDeviceScanner(ti, timeout), nil
	}

	return nil, fmt.Errorf("Unknown scan type '%s'", scanTypeStr)
}

var rootCmd = &cobra.Command{
	Use:   "furious",
	Short: "Furious is a IP/port scanner",
	Long:  `An IP/port scanner for identifying hosts/services remotely.`,
	Run: func(cmd *cobra.Command, args []string) {

		if versionRequested {
			v := version.Version
			if v == "" {
				v = "development version"
			}
			fmt.Printf("furious %s\n", v)
			return
		}

		if debug {
			log.SetLevel(log.DebugLevel)
		}

		if len(args) == 0 {
			fmt.Println("Please specify a target")
			os.Exit(1)
		}

		ports, err := getPorts(portSelection)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		ctx, cancel := context.WithCancel(context.Background())

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			<-c
			fmt.Println("Scan cancelled. Requesting stop...")
			cancel()
		}()

		startTime := time.Now()
		if !jsonOutput {
			fmt.Printf("\nStarting scan at %s\n\n", startTime.String())
		}
		for _, target := range args {

			targetIterator := scan.NewTargetIterator(target)

			// creating scanner
			scanner, err := createScanner(targetIterator, scanType, time.Millisecond*time.Duration(timeoutMS), parallelism)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			log.Debugf("Starting scanner...")
			if err := scanner.Start(); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			log.Debugf("Scanning target %s...", target)

			results, err := scanner.Scan(ctx, ports)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			for _, result := range results {
				if jsonOutput {
					scanner.OutputResultJSON(result)
					continue
				}
				if !hideUnavailableHosts || result.IsHostUp() {
					scanner.OutputResult(result)
				}
			}

		}

		if !jsonOutput {
			fmt.Printf("Scan complete in %s.\n", time.Since(startTime).String())
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getPorts(selection string) ([]int, error) {
	if selection == "" {
		return scan.DefaultPorts, nil
	}
	ports := []int{}
	ranges := strings.Split(selection, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("Invalid port selection segment: '%s'", r)
			}

			p1, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("Invalid port number: '%s'", parts[0])
			}

			p2, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("Invalid port number: '%s'", parts[1])
			}

			if p1 > p2 {
				return nil, fmt.Errorf("Invalid port range: %d-%d", p1, p2)
			}

			for i := p1; i <= p2; i++ {
				ports = append(ports, i)
			}

		} else {
			if port, err := strconv.Atoi(r); err != nil {
				return nil, fmt.Errorf("Invalid port number: '%s'", r)
			} else {
				ports = append(ports, port)
			}
		}
	}
	return ports, nil
}
