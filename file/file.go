package file

import (
	"bufio"
	"encoding/base64"
	"os"
)

func ReadBase64Lines(filename string) ([][]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var res [][]byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := scanner.Text()
		b, err := base64.StdEncoding.DecodeString(l)
		if err != nil {
			return nil, err
		}
		res = append(res, b)
	}
	return res, nil

}
