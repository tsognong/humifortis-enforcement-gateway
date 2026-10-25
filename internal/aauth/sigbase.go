package aauth

import (
	"net/http"
	"strings"
)

// Request is what the verifier needs to know of the request: what nginx's auth_request reports about the ORIGINAL request, and
// its headers. Method, Authority, Path and Query are those of the request the agent signed.
type Request struct {
	Method    string
	Authority string // Host as the client sent it (lower-cased by the verifier; the default port is dropped)
	Path      string // without the query string
	Query     string // without the leading "?"
	Scheme    string
	Header    http.Header
	// SourceIP is the address of the caller as the trusted proxy saw it (audit only).
	SourceIP string
}

// signatureInput is a Signature-Input member of the signature the request carries.
type signatureInput struct {
	label      string
	components []string
	raw        string // the member value as received: the @signature-params line of the base
	created    int64
	hasCreated bool
	expires    int64
	hasExpires bool
	hasAlg     bool
	hasKeyID   bool
	nonce      bool
}

// requiredComponents are those every AAuth signature must cover (draft 12.8.3); "authorization" is added when the request
// presents an AAuth-Access credential.
func requiredComponents(authorizationPresent bool) []string {
	base := []string{"@method", "@authority", "@path", "signature-key"}
	if authorizationPresent {
		base = append(base, "authorization")
	}
	return base
}

// parseSignatureInput reads the member of Signature-Input named label: the covered components and the parameters.
func parseSignatureInput(fields []string, label string) (signatureInput, *Error) {
	if len(fields) == 0 {
		return signatureInput{}, failDetail(InvalidRequest, "Signature-Input is missing")
	}
	dict, err := parseDictionary(combineField(fields))
	if err != nil {
		return signatureInput{}, failDetail(InvalidRequest, "Signature-Input is not a structured field")
	}
	var m *member
	for i := range dict {
		if dict[i].key == label {
			m = &dict[i]
		}
	}
	if m == nil || !m.inner {
		return signatureInput{}, failDetail(InvalidRequest, "Signature-Input has no signature of that label")
	}
	in := signatureInput{label: label, raw: m.raw}
	seen := map[string]bool{}
	for _, c := range m.items {
		if c.item.kind != kindString {
			return signatureInput{}, failDetail(InvalidRequest, "a covered component is a string")
		}
		if len(c.params) > 0 {
			return signatureInput{}, failDetail(InvalidInput, "component parameters (;sf, ;key, ;name...) are not part of the profile")
		}
		name := c.item.str
		if name != strings.ToLower(name) {
			return signatureInput{}, failDetail(InvalidRequest, "a component identifier is lower case")
		}
		if seen[name] {
			return signatureInput{}, failDetail(InvalidRequest, "a component is covered twice")
		}
		seen[name] = true
		in.components = append(in.components, name)
	}
	for _, p := range m.params {
		switch p.key {
		case "created":
			if p.val.kind != kindInteger {
				return signatureInput{}, failDetail(InvalidRequest, "created is an integer")
			}
			in.created, in.hasCreated = p.val.num, true
		case "expires":
			if p.val.kind != kindInteger {
				return signatureInput{}, failDetail(InvalidRequest, "expires is an integer")
			}
			in.expires, in.hasExpires = p.val.num, true
		case "alg":
			in.hasAlg = true
		case "keyid":
			in.hasKeyID = true
		case "nonce":
			in.nonce = true
		case "tag":
		default:
			return signatureInput{}, failDetail(InvalidRequest, "unknown signature parameter")
		}
	}
	return in, nil
}

// signatureBase builds the RFC 9421 section 2.5 signature base of the request for the covered components. A component the
// request cannot supply is an error (invalid_request: the signature covers something that is not there).
func signatureBase(req Request, in signatureInput) (string, *Error) {
	var b strings.Builder
	for _, name := range in.components {
		value, err := componentValue(req, name)
		if err != nil {
			return "", err
		}
		b.WriteString(`"` + name + `": ` + value + "\n")
	}
	b.WriteString(`"@signature-params": ` + in.raw)
	return b.String(), nil
}

func componentValue(req Request, name string) (string, *Error) {
	switch name {
	case "@method":
		if req.Method == "" {
			return "", failDetail(InvalidRequest, "no request method")
		}
		return req.Method, nil
	case "@authority":
		a := strings.ToLower(strings.TrimSpace(req.Authority))
		if a == "" {
			return "", failDetail(InvalidRequest, "no authority")
		}
		scheme := strings.ToLower(req.Scheme)
		if scheme == "" || scheme == "https" {
			a = strings.TrimSuffix(a, ":443")
		}
		if scheme == "http" {
			a = strings.TrimSuffix(a, ":80")
		}
		return a, nil
	case "@path":
		if req.Path == "" {
			return "/", nil
		}
		return req.Path, nil
	case "@query":
		return "?" + req.Query, nil
	case "@scheme":
		if req.Scheme == "" {
			return "https", nil
		}
		return strings.ToLower(req.Scheme), nil
	}
	if strings.HasPrefix(name, "@") {
		return "", failDetail(InvalidInput, "the derived component "+name+" is not part of the profile")
	}
	values := req.Header.Values(name)
	if len(values) == 0 {
		return "", failDetail(InvalidRequest, "the signature covers "+name+", which the request does not carry")
	}
	trimmed := make([]string, len(values))
	for i, v := range values {
		if strings.ContainsAny(v, "\r\n") {
			return "", failDetail(InvalidRequest, "a header value contains a line break")
		}
		trimmed[i] = strings.TrimSpace(v)
	}
	return strings.Join(trimmed, ", "), nil
}

// covers reports whether the list contains every required component, and which are missing.
func missingComponents(have []string, required []string) []string {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	var missing []string
	for _, r := range required {
		if !set[r] {
			missing = append(missing, r)
		}
	}
	return missing
}
