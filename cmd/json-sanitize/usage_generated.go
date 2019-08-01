// Code generated by github.com/artyom/usagegen; DO NOT EDIT.

package main

const usage = "Command json-sanitize sanitizes string fields of json input replacing them with\n\"REDACTED\" value.\n\nCommand takes list of case-sensitive field names as its arguments, then reads\narbitrary json structure over stdin and writes sanitized version to stdout.\n\nFor example, the following call:\n\n\techo '{\"foo\":\"foo\", \"bar\":\"bar\"}' | json-sanitize foo\n\nwill produce this:\n\n\t{\"foo\":\"REDACTED\",\"bar\":\"bar\"}\n"