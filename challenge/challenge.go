package challenge

import "fmt"

type wrongOutputErr struct {
	expected interface{}
	actual interface{}
}

func (err *wrongOutputErr) Error() string {
	return fmt.Sprintf("expected output does not match actual output:\nexpected: %v\nactual:   %v", err.expected, err.actual)
}

func WrongOutputErr(expected, actual interface{}) error {
	return &wrongOutputErr{
		expected: expected,
		actual: actual,
	}
}

type Challenge interface {
	Solve() error
}