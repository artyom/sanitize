package sanitize_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/artyom/sanitize"
)

const input = `{"Msg": "Hi", "Obj": {"a":1, "c":"C", "b":null}, "Arr": ["a","b","c"], "Null": null, "Num": 1.234}`
const want = `{"Msg": "********", "Obj": {"a": 1, "c": "********", "b": null}, "Arr": ["a", "b", "c"], "Null": null, "Num": 1.234}`

var re = regexp.MustCompile(`(?i)msg$`)
var fset = map[string]struct{}{
	"a": struct{}{},
	"b": struct{}{},
	"c": struct{}{},
}

func TestMessageFunc(t *testing.T) {
	fn := func(key, val string) (string, bool) {
		switch key {
		case "Msg", "a", "b", "c":
			return sanitize.Mask, true
		}
		return "", false
	}
	dst, err := sanitize.MessageFunc(nil, []byte(input), fn)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(dst) {
		t.Fatal("invalid output:", string(dst))
	}
	if got := string(dst); got != want {
		t.Log("input:", input)
		t.Log("want:", want)
		t.Fatal("got:", got)
	}
}

func TestStream(t *testing.T) {
	buf := new(bytes.Buffer)
	if err := sanitize.Stream(buf, strings.NewReader(input), fset, re); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatal("invalid output:", buf)
	}
	if buf.String() != want {
		t.Log("input:", input)
		t.Log("want:", want)
		t.Fatal("got:", buf)
	}
}

func TestMessage(t *testing.T) {
	dst, err := sanitize.Message(nil, []byte(input), fset, re)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(dst) {
		t.Fatal("invalid output:", string(dst))
	}
	if got := string(dst); got != want {
		t.Log("input:", input)
		t.Log("want:", want)
		t.Fatal("got:", got)
	}
}

func BenchmarkStream(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sanitize.Stream(ioutil.Discard, strings.NewReader(input), fset, re); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessage(b *testing.B) {
	dst := make([]byte, len(input))
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	var err error
	for i := 0; i < b.N; i++ {
		if dst, err = sanitize.Message(dst, []byte(input), fset, re); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessageFunc(b *testing.B) {
	fn := func(key, val string) (string, bool) {
		switch key {
		case "Msg", "a", "b", "c":
			return sanitize.Mask, true
		}
		return "", false
	}
	dst := make([]byte, len(input))
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	var err error
	for i := 0; i < b.N; i++ {
		if dst, err = sanitize.MessageFunc(dst, []byte(input), fn); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessage_Custom(b *testing.B) {
	name := os.Getenv("JSON")
	fields := os.Getenv("FIELDS")
	if name == "" || fields == "" {
		b.Skip("either JSON or FIELDS environment is empty, skipping")
	}
	src, err := ioutil.ReadFile(name)
	if err != nil {
		b.Fatal(err)
	}
	if !json.Valid(src) {
		b.Fatalf("file %q does not contain valid json", name)
	}
	fset := make(map[string]struct{})
	for _, f := range strings.Split(fields, ",") {
		fset[f] = struct{}{}
	}
	dst := make([]byte, len(src))
	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if dst, err = sanitize.Message(dst, src, fset, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessageFunc_Custom(b *testing.B) {
	name := os.Getenv("JSON")
	fields := os.Getenv("FIELDS")
	if name == "" || fields == "" {
		b.Skip("either JSON or FIELDS environment is empty, skipping")
	}
	src, err := ioutil.ReadFile(name)
	if err != nil {
		b.Fatal(err)
	}
	if !json.Valid(src) {
		b.Fatalf("file %q does not contain valid json", name)
	}
	fset := make(map[string]struct{})
	for _, f := range strings.Split(fields, ",") {
		fset[f] = struct{}{}
	}
	fn := func(key, val string) (string, bool) {
		if _, ok := fset[key]; ok {
			return sanitize.Mask, true
		}
		return "", false
	}
	dst := make([]byte, len(src))
	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if dst, err = sanitize.MessageFunc(dst, src, fn); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStream_Custom(b *testing.B) {
	name := os.Getenv("JSON")
	fields := os.Getenv("FIELDS")
	if name == "" || fields == "" {
		b.Skip("either JSON or FIELDS environment is empty, skipping")
	}
	src, err := ioutil.ReadFile(name)
	if err != nil {
		b.Fatal(err)
	}
	if !json.Valid(src) {
		b.Fatalf("file %q does not contain valid json", name)
	}
	fset := make(map[string]struct{})
	for _, f := range strings.Split(fields, ",") {
		fset[f] = struct{}{}
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err = sanitize.Stream(ioutil.Discard, bytes.NewReader(src), fset, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func Example() {
	msg := `{"ID": 42, "Name": "Zaphod Beeblebrox", "Secret": "Trillian"}`

	// exact field name matches
	fields := map[string]struct{}{
		"Name": struct{}{},
	}
	// matches fields starting with "secret" in a case-insensitive way
	re := regexp.MustCompile(`(?i)secret`)

	out, err := sanitize.Message(nil, []byte(msg), fields, re)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
	// Output:
	// {"ID": 42, "Name": "********", "Secret": "********"}
}

func ExampleMessageFunc() {
	msg := `{"ID": 42, "Name": "Zaphod Beeblebrox", "Secret": "Trillian"}`

	fn := func(key, value string) (string, bool) {
		if key == "Secret" {
			return sanitize.Mask, true
		}
		return "", false
	}

	out, err := sanitize.MessageFunc(nil, []byte(msg), fn)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
	// Output:
	// {"ID": 42, "Name": "Zaphod Beeblebrox", "Secret": "********"}
}
