// Command json-sanitize sanitizes string fields of json input replacing them
// with "REDACTED" value.
//
// Command takes list of case-sensitive field names as its arguments, then reads
// arbitrary json structure over stdin and writes sanitized version to stdout.
//
// For example, the following call:
//
//	echo '{"foo":"foo", "bar":"bar"}' | json-sanitize foo
//
// will produce this:
//
// 	{"foo":"REDACTED","bar":"bar"}
package main

import (
	"os"

	"github.com/artyom/sanitize"
)

func main() {
	if len(os.Args) < 2 {
		os.Stderr.WriteString(usage)
		os.Exit(2)
	}
	if err := run(os.Args[1:]); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func run(keys []string) error {
	m := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		m[k] = struct{}{}
	}
	fn := func(key, _ string) (string, bool) {
		if _, ok := m[key]; ok {
			return "REDACTED", true
		}
		return "", false
	}
	return sanitize.Stream(os.Stdout, os.Stdin, fn)
}

//go:generate usagegen
