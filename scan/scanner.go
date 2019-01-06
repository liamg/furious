package scan

type Scanner interface {
	Stop()
	Start() error
	Scan(ports []int) ([]Result, error)
	OutputResult(result Result)
}
