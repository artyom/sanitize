// Package sanitize provides functions to sanitize (anonymize) certain string
// fields of arbitrary json messages.
//
// Note that the main use case for this package is handling of opaque json
// messages, not anything with the known structure, which is better handled
// explicitly by sanitizing data and then marshaling sanitized representation.
package sanitize

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

var errInvalidArguents = errors.New("sanitize: either field set or regexp must be provided")

// Stream sanitizes json payload read from r writing result to w. fset is
// a set of exact field names to be filtered, re is a regular expression to
// match against field names to be filtered. Either of fset or re can be nil,
// but not both. Matched string fields are replaced with Mask value.
//
// For smaller messages it is more effective to use Message function.
func Stream(w io.Writer, r io.Reader, fset map[string]struct{}, re *regexp.Regexp) error {
	if re == nil && len(fset) == 0 {
		return errInvalidArguents
	}
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var ds []rune // stack of separators
	var cnt int
	var sanitize bool
	var prevDelim byte
	var tmp []byte
	for {
		var delim byte = comma
		t, err := dec.Token()
		if err == io.EOF {
			return bw.Flush()
		}
		if err != nil {
			return err
		}
		switch v := t.(type) {
		case string:
			if sanitize && prevDelim == ':' {
				v = Mask
				sanitize = false
			}
			if cnt%2 != 0 && len(ds) > 0 && ds[len(ds)-1] == '{' {
				delim = colon
				if _, ok := fset[v]; ok || (re != nil && re.MatchString(v)) {
					sanitize = true
				}
			}
			bw.Write(strconv.AppendQuote(tmp[:0], v))
		case bool:
			if v {
				bw.WriteString("true")
			} else {
				bw.WriteString("false")
			}
		case json.Delim:
			switch v {
			case '{', '[':
				ds = append(ds, rune(v))
			case '}', ']':
				if len(ds) > 0 {
					ds = ds[:len(ds)-1]
				}
			}
			cnt = 0
			prevDelim = 0
			bw.WriteRune(rune(v))
		case json.Number:
			bw.WriteString(string(v))
		case nil:
			bw.WriteString("null")
		default:
			return fmt.Errorf("unknown json token: %v", v)
		}
		cnt++
		if dec.More() {
			if v, ok := t.(json.Delim); !ok || v == '}' || v == ']' {
				prevDelim = delim
				bw.Write([]byte{delim, ' '})
			}
		}
	}
}

// Message sanitizes json payload from src and returns its sanitized
// representation. If dst is non-nil, it is used as a scratch buffer to reduce
// allocations. fset is a set of exact field names to be filtered, re is
// a regular expression to match against field names to be filtered. Either of
// fset or re can be nil, but not both. Matched string fields are replaced with
// Mask value.
func Message(dst, src []byte, fset map[string]struct{}, re *regexp.Regexp) ([]byte, error) {
	if re == nil && len(fset) == 0 {
		return nil, errInvalidArguents
	}
	if len(dst) > 0 {
		dst = dst[:0]
	}
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	var ds []rune // stack of separators
	var cnt int
	var sanitize bool
	var prevDelim byte
	for {
		var delim byte = comma
		t, err := dec.Token()
		if err == io.EOF {
			return dst, nil
		}
		if err != nil {
			return nil, err
		}
		switch v := t.(type) {
		case string:
			if sanitize && prevDelim == ':' {
				v = Mask
				sanitize = false
			}
			if cnt%2 != 0 && len(ds) > 0 && ds[len(ds)-1] == '{' {
				delim = colon
				if _, ok := fset[v]; ok || (re != nil && re.MatchString(v)) {
					sanitize = true
				}
			}
			dst = strconv.AppendQuote(dst, v)
		case bool:
			dst = strconv.AppendBool(dst, v)
		case json.Delim:
			switch v {
			case '{', '[':
				ds = append(ds, rune(v))
			case '}', ']':
				if len(ds) > 0 {
					ds = ds[:len(ds)-1]
				}
			}
			cnt = 0
			prevDelim = 0
			dst = append(dst, byte(v))
		case json.Number:
			dst = append(dst, string(v)...)
		case nil:
			dst = append(dst, "null"...)
		default:
			return nil, fmt.Errorf("unknown json token: %v", v)
		}
		cnt++
		if dec.More() {
			if v, ok := t.(json.Delim); !ok || v == '}' || v == ']' {
				prevDelim = delim
				dst = append(dst, delim, ' ')
			}
		}
	}
}

// FieldFunc is called on each string attribute of JSON object processed by
// MessageFunc. Arguments provided are key/value pair of JSON payload, if
// function returns true for doReplace, attribute value is substituted by
// newValue.
type FieldFunc func(key, value string) (newValue string, doReplace bool)

// MessageFunc sanitizes json payload from src and returns its sanitized
// representation. If dst is non-nil, it is used as a scratch buffer to reduce
// allocations. fn must be a non-nil FieldFunc called on each string key/value
// pair of json payload.
func MessageFunc(dst, src []byte, fn FieldFunc) ([]byte, error) {
	if fn == nil {
		return nil, errors.New("sanitize: fn cannot not be nil")
	}
	if len(dst) > 0 {
		dst = dst[:0]
	}
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	var ds []rune // stack of separators
	var cnt int
	var sanitize bool
	var prevDelim byte
	var key string
	for {
		var delim byte = comma
		t, err := dec.Token()
		if err == io.EOF {
			return dst, nil
		}
		if err != nil {
			return nil, err
		}
		switch v := t.(type) {
		case string:
			if sanitize && prevDelim == ':' {
				if val, ok := fn(key, v); ok {
					v = val
				}
				sanitize = false
			}
			if cnt%2 != 0 && len(ds) > 0 && ds[len(ds)-1] == '{' {
				delim = colon
				key = v
				sanitize = true
			}
			dst = strconv.AppendQuote(dst, v)
		case bool:
			dst = strconv.AppendBool(dst, v)
		case json.Delim:
			switch v {
			case '{', '[':
				ds = append(ds, rune(v))
			case '}', ']':
				if len(ds) > 0 {
					ds = ds[:len(ds)-1]
				}
			}
			cnt = 0
			prevDelim = 0
			dst = append(dst, byte(v))
		case json.Number:
			dst = append(dst, string(v)...)
		case nil:
			dst = append(dst, "null"...)
		default:
			return nil, fmt.Errorf("unknown json token: %v", v)
		}
		cnt++
		if dec.More() {
			if v, ok := t.(json.Delim); !ok || v == '}' || v == ']' {
				prevDelim = delim
				dst = append(dst, delim, ' ')
			}
		}
	}
}

// Mask replaces sensitive fields
const Mask = "********"

const (
	comma = ','
	colon = ':'
)
