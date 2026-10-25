package aauth

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// A parser of the subset of RFC 8941 (Structured Field Values) that HTTP Message Signatures and AAuth use: dictionaries whose
// members are items or inner lists of items, each with parameters; items are strings, tokens, integers and byte sequences.
// Anything else (decimals, dates, nested inner lists, booleans as items of a signature) is a parse error: the profile does not
// use it and a verifier that accepted it would be guessing.

// itemKind is the type of a bare item.
type itemKind int

const (
	kindString itemKind = iota
	kindToken
	kindInteger
	kindBytes
	kindBoolean
)

// item is a bare item.
type item struct {
	kind itemKind
	str  string // string, token
	num  int64
	raw  []byte // byte sequence
	b    bool
}

// param is one parameter of an item or an inner list, in order.
type param struct {
	key string
	val item
}

// member is a dictionary member: an item with parameters, or an inner list of items with parameters. raw is the exact text of
// the member's value as received (RFC 9421 asks a verifier to reuse it as the @signature-params value, so that a different
// serialisation of the same data can never change the signature base).
type member struct {
	key    string
	inner  bool
	item   item
	items  []itemWithParams // inner list
	params []param
	raw    string
}

type itemWithParams struct {
	item   item
	params []param
}

type sfvParser struct {
	s   string
	pos int
}

// parseDictionary parses a dictionary field value (already combined: several field lines are joined with ", ").
func parseDictionary(s string) ([]member, error) {
	p := &sfvParser{s: s}
	p.skipSP()
	var out []member
	seen := map[string]bool{}
	for p.pos < len(p.s) {
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate dictionary key %q", key)
		}
		seen[key] = true
		m := member{key: key}
		start := p.pos
		if p.peek() == '=' {
			p.pos++
			valStart := p.pos
			if p.peek() == '(' {
				items, params, err := p.innerList()
				if err != nil {
					return nil, err
				}
				m.inner, m.items, m.params = true, items, params
			} else {
				it, err := p.bareItem()
				if err != nil {
					return nil, err
				}
				params, err := p.params()
				if err != nil {
					return nil, err
				}
				m.item, m.params = it, params
			}
			m.raw = p.s[valStart:p.pos]
		} else {
			// a key with no value is the boolean true, with parameters
			params, err := p.params()
			if err != nil {
				return nil, err
			}
			m.item, m.params = item{kind: kindBoolean, b: true}, params
			m.raw = p.s[start:p.pos]
		}
		out = append(out, m)
		p.skipOWS()
		if p.pos >= len(p.s) {
			break
		}
		if p.peek() != ',' {
			return nil, fmt.Errorf("expected a comma at offset %d", p.pos)
		}
		p.pos++
		p.skipOWS()
		if p.pos >= len(p.s) {
			return nil, fmt.Errorf("trailing comma")
		}
	}
	return out, nil
}

func (p *sfvParser) peek() byte {
	if p.pos >= len(p.s) {
		return 0
	}
	return p.s[p.pos]
}

func (p *sfvParser) skipSP() {
	for p.pos < len(p.s) && p.s[p.pos] == ' ' {
		p.pos++
	}
}

func (p *sfvParser) skipOWS() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
}

func isLcAlpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool   { return c >= '0' && c <= '9' }

// key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
func (p *sfvParser) key() (string, error) {
	start := p.pos
	if p.pos >= len(p.s) || !(isLcAlpha(p.s[p.pos]) || p.s[p.pos] == '*') {
		return "", fmt.Errorf("a key starts with a lower case letter or *, at offset %d", p.pos)
	}
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if isLcAlpha(c) || isDigit(c) || c == '_' || c == '-' || c == '.' || c == '*' {
			p.pos++
			continue
		}
		break
	}
	return p.s[start:p.pos], nil
}

func (p *sfvParser) params() ([]param, error) {
	var out []param
	for p.peek() == ';' {
		p.pos++
		p.skipSP()
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		val := item{kind: kindBoolean, b: true}
		if p.peek() == '=' {
			p.pos++
			val, err = p.bareItem()
			if err != nil {
				return nil, err
			}
		}
		for _, existing := range out {
			if existing.key == key {
				return nil, fmt.Errorf("duplicate parameter %q", key)
			}
		}
		out = append(out, param{key: key, val: val})
	}
	return out, nil
}

func (p *sfvParser) innerList() ([]itemWithParams, []param, error) {
	if p.peek() != '(' {
		return nil, nil, fmt.Errorf("expected an inner list")
	}
	p.pos++
	var items []itemWithParams
	for {
		p.skipSP()
		if p.pos >= len(p.s) {
			return nil, nil, fmt.Errorf("unterminated inner list")
		}
		if p.peek() == ')' {
			p.pos++
			params, err := p.params()
			return items, params, err
		}
		it, err := p.bareItem()
		if err != nil {
			return nil, nil, err
		}
		params, err := p.params()
		if err != nil {
			return nil, nil, err
		}
		items = append(items, itemWithParams{item: it, params: params})
		if c := p.peek(); c != ' ' && c != ')' {
			return nil, nil, fmt.Errorf("items of an inner list are separated by a space, at offset %d", p.pos)
		}
	}
}

func (p *sfvParser) bareItem() (item, error) {
	switch c := p.peek(); {
	case c == '"':
		return p.str()
	case c == ':':
		return p.bytes()
	case c == '?':
		return p.boolean()
	case c == '-' || isDigit(c):
		return p.integer()
	case isAlphaByte(c) || c == '*':
		return p.token()
	}
	return item{}, fmt.Errorf("unexpected character at offset %d", p.pos)
}

func isAlphaByte(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func (p *sfvParser) str() (item, error) {
	p.pos++ // opening quote
	var b strings.Builder
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		p.pos++
		switch {
		case c == '\\':
			if p.pos >= len(p.s) {
				return item{}, fmt.Errorf("unterminated escape")
			}
			n := p.s[p.pos]
			p.pos++
			if n != '"' && n != '\\' {
				return item{}, fmt.Errorf("invalid escape")
			}
			b.WriteByte(n)
		case c == '"':
			return item{kind: kindString, str: b.String()}, nil
		case c < 0x20 || c > 0x7e:
			return item{}, fmt.Errorf("invalid character in a string")
		default:
			b.WriteByte(c)
		}
	}
	return item{}, fmt.Errorf("unterminated string")
}

func (p *sfvParser) token() (item, error) {
	start := p.pos
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if isAlphaByte(c) || isDigit(c) || strings.IndexByte(":/!#$%&'*+-.^_`|~", c) >= 0 {
			p.pos++
			continue
		}
		break
	}
	return item{kind: kindToken, str: p.s[start:p.pos]}, nil
}

func (p *sfvParser) integer() (item, error) {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
	}
	digits := 0
	for p.pos < len(p.s) && isDigit(p.s[p.pos]) {
		p.pos++
		digits++
	}
	if digits == 0 || digits > 15 {
		return item{}, fmt.Errorf("invalid integer")
	}
	if p.peek() == '.' {
		return item{}, fmt.Errorf("decimals are not used by this profile")
	}
	n, err := strconv.ParseInt(p.s[start:p.pos], 10, 64)
	if err != nil {
		return item{}, err
	}
	return item{kind: kindInteger, num: n}, nil
}

func (p *sfvParser) bytes() (item, error) {
	p.pos++ // opening colon
	start := p.pos
	for p.pos < len(p.s) && p.s[p.pos] != ':' {
		p.pos++
	}
	if p.pos >= len(p.s) {
		return item{}, fmt.Errorf("unterminated byte sequence")
	}
	raw, err := base64.StdEncoding.DecodeString(p.s[start:p.pos])
	if err != nil {
		return item{}, fmt.Errorf("invalid base64 in a byte sequence")
	}
	p.pos++
	return item{kind: kindBytes, raw: raw}, nil
}

func (p *sfvParser) boolean() (item, error) {
	p.pos++
	switch p.peek() {
	case '1':
		p.pos++
		return item{kind: kindBoolean, b: true}, nil
	case '0':
		p.pos++
		return item{kind: kindBoolean, b: false}, nil
	}
	return item{}, fmt.Errorf("invalid boolean")
}

// findParam is the parameter of that name.
func findParam(params []param, key string) (item, bool) {
	for _, p := range params {
		if p.key == key {
			return p.val, true
		}
	}
	return item{}, false
}

// combineField joins the lines of one field the way a recipient must before parsing it as a structured field (RFC 9110 5.3).
func combineField(values []string) string {
	trimmed := make([]string, 0, len(values))
	for _, v := range values {
		trimmed = append(trimmed, strings.TrimSpace(v))
	}
	return strings.Join(trimmed, ", ")
}
