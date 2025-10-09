// +build !linux,!darwin

package scan

import (
	"fmt"
	"runtime"
)

type fallbackRouter struct{}

func newDarwinRouter() (Router, error) {
	return nil, fmt.Errorf("stealth scanning not supported on %s - use connect scan instead", runtime.GOOS)
}

func newLinuxRouter() (Router, error) {
	return nil, fmt.Errorf("stealth scanning not supported on %s - use connect scan instead", runtime.GOOS)
}