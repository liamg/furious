package scan

type Scanner interface {
	Stop()
	Start() error
	Scan(targetIterator *TargetIterator, ports []int) ([]Result, error)
	OutputResult(result Result)
}
