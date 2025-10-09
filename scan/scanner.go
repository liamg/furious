package scan

import "context"

type Scanner interface {
	Stop()
	Start() error
	Scan(ctx context.Context, ports []int) ([]Result, error)
	OutputResult(result Result)
}
