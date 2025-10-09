package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {

	resp, err := http.Get("https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv")
	if err != nil {
		panic(err)
	}

	output, err := os.Create("./scan/known.go")
	if err != nil {
		panic(err)
	}
	output.Seek(0, 0)
	defer output.Close()

	output.Write([]byte(`package scan

// data from https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
var knownPorts = map[int]string{`))

	lastPort := ""
	reader := csv.NewReader(resp.Body)
	for {
		// read one row from csv
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}

		if len(record) < 3 || record[2] != "tcp" || record[0] == "" || record[1] == "" || record[1] == lastPort {
			continue
		}

		lastPort = record[1]
		output.Write([]byte(fmt.Sprintf(`
	%s: "%s",`, record[1], record[0])))

	}

	output.Write([]byte(`
}
`))
}
