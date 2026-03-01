package fingerprint

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

//go:embed technologies/*.json
var techFS embed.FS

type DB struct {
	entries []*entry
}

type Hit struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Categories []int  `json:"categories"`
}

type entry struct {
	name     string
	cats     []int
	headers  []hdrMatch
	bodyPats []*cpat
	srcPats  []*cpat
	urlPats  []*cpat
	cookies  []ckMatch
	metas    []metaMatch
}

type cpat struct {
	re         *regexp.Regexp
	hasVersion bool
}

type hdrMatch struct {
	name string
	pat  *cpat
}

type ckMatch struct {
	nameRe  *regexp.Regexp
	nameLit string
	pat     *cpat
}

type metaMatch struct {
	name string
	pat  *cpat
}

type rawTech struct {
	Cats      []int             `json:"cats"`
	Headers   map[string]string `json:"headers"`
	HTML      []string          `json:"html"`
	Scripts   []string          `json:"scripts"`
	ScriptSrc []string          `json:"scriptSrc"`
	Cookies   map[string]string `json:"cookies"`
	URL       []string          `json:"url"`
	Meta      map[string]string `json:"meta"`
}

var (
	rScriptSrc = regexp.MustCompile(`(?i)<script[^>]+\bsrc\s*=\s*["']([^"']*)["']`)
	rMetaNC    = regexp.MustCompile(`(?i)<meta[^>]+\bname\s*=\s*["']([^"']*)["'][^>]*\bcontent\s*=\s*["']([^"']*)["']`)
	rMetaCN    = regexp.MustCompile(`(?i)<meta[^>]+\bcontent\s*=\s*["']([^"']*)["'][^>]*\bname\s*=\s*["']([^"']*)["']`)

	defaultOnce sync.Once
	defaultDB   *DB
)

func Default() *DB {
	defaultOnce.Do(func() { defaultDB = New() })
	return defaultDB
}

func New() *DB {
	db := &DB{}
	entries, _ := techFS.ReadDir("technologies")
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := fs.ReadFile(techFS, "technologies/"+e.Name())
		if err != nil {
			continue
		}
		var raw map[string]rawTech
		if err := json.Unmarshal(data, &raw); err != nil {
			continue
		}
		for name, tech := range raw {
			if ent := buildEntry(name, tech); ent != nil {
				db.entries = append(db.entries, ent)
			}
		}
	}
	return db
}

func buildEntry(name string, rt rawTech) *entry {
	e := &entry{name: name, cats: rt.Cats}

	for hdr, rawPat := range rt.Headers {
		if p := compilePat(rawPat); p != nil {
			e.headers = append(e.headers, hdrMatch{name: strings.ToLower(hdr), pat: p})
		}
	}
	for _, rawPat := range rt.HTML {
		if p := compilePat(rawPat); p != nil {
			e.bodyPats = append(e.bodyPats, p)
		}
	}
	for _, rawPat := range rt.Scripts {
		if p := compilePat(rawPat); p != nil {
			e.bodyPats = append(e.bodyPats, p)
		}
	}
	for _, rawPat := range rt.ScriptSrc {
		if p := compilePat(rawPat); p != nil {
			e.srcPats = append(e.srcPats, p)
		}
	}
	for _, rawPat := range rt.URL {
		if p := compilePat(rawPat); p != nil {
			e.urlPats = append(e.urlPats, p)
		}
	}
	for ckName, rawPat := range rt.Cookies {
		p := compilePat(rawPat)
		if p == nil {
			continue
		}
		cm := ckMatch{pat: p}
		if containsRegexChars(ckName) {
			if nr, err := regexp.Compile(`(?i)^(?:` + ckName + `)$`); err == nil {
				cm.nameRe = nr
			} else {
				cm.nameLit = strings.ToLower(ckName)
			}
		} else {
			cm.nameLit = strings.ToLower(ckName)
		}
		e.cookies = append(e.cookies, cm)
	}
	for metaName, rawPat := range rt.Meta {
		if p := compilePat(rawPat); p != nil {
			e.metas = append(e.metas, metaMatch{name: strings.ToLower(metaName), pat: p})
		}
	}
	return e
}

func compilePat(raw string) *cpat {
	parts := strings.Split(raw, `\;`)
	patStr := parts[0]
	hasVersion := false
	for _, ann := range parts[1:] {
		if strings.HasPrefix(ann, "version:") {
			hasVersion = true
		}
	}
	patStr = strings.TrimSpace(patStr)
	if patStr == "" {
		return &cpat{hasVersion: hasVersion}
	}
	re, err := regexp.Compile(`(?i)` + patStr)
	if err != nil {
		return nil
	}
	return &cpat{re: re, hasVersion: hasVersion}
}

func (p *cpat) matchStr(s string) (bool, string) {
	if p.re == nil {
		return s != "", ""
	}
	m := p.re.FindStringSubmatch(s)
	if m == nil {
		return false, ""
	}
	var ver string
	if p.hasVersion && len(m) > 1 {
		ver = m[1]
	}
	return true, ver
}

func containsRegexChars(s string) bool {
	return strings.ContainsAny(s, `\^$*+?.()|{}[]`)
}

type normCookie struct {
	nameLower string
	value     string
}

func (db *DB) Match(reqURL string, respHeaders http.Header, cookies []*http.Cookie, body []byte) []Hit {
	bodyStr := string(body)

	var srcVals []string
	for _, m := range rScriptSrc.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) > 1 {
			srcVals = append(srcVals, m[1])
		}
	}

	metaMap := extractMetas(bodyStr)

	var nc []normCookie
	for _, c := range cookies {
		nc = append(nc, normCookie{nameLower: strings.ToLower(c.Name), value: c.Value})
	}

	seen := make(map[string]bool, len(db.entries))
	var hits []Hit
	for _, e := range db.entries {
		if seen[e.name] {
			continue
		}
		if matched, ver := e.try(reqURL, respHeaders, bodyStr, srcVals, metaMap, nc); matched {
			seen[e.name] = true
			hits = append(hits, Hit{Name: e.name, Version: ver, Categories: e.cats})
		}
	}
	return hits
}

func (e *entry) try(reqURL string, hdrs http.Header, body string, srcVals []string, metas map[string]string, cookies []normCookie) (bool, string) {
	for _, hm := range e.headers {
		vals := hdrs[http.CanonicalHeaderKey(hm.name)]
		if len(vals) == 0 {
			continue
		}
		if ok, ver := hm.pat.matchStr(vals[0]); ok {
			return true, ver
		}
	}
	for _, p := range e.bodyPats {
		if ok, ver := p.matchStr(body); ok {
			return true, ver
		}
	}
	for _, p := range e.srcPats {
		for _, src := range srcVals {
			if ok, ver := p.matchStr(src); ok {
				return true, ver
			}
		}
	}
	for _, p := range e.urlPats {
		if ok, ver := p.matchStr(reqURL); ok {
			return true, ver
		}
	}
	for _, cm := range e.cookies {
		for _, ck := range cookies {
			var nameOK bool
			if cm.nameRe != nil {
				nameOK = cm.nameRe.MatchString(ck.nameLower)
			} else {
				nameOK = cm.nameLit == ck.nameLower
			}
			if nameOK {
				if ok, ver := cm.pat.matchStr(ck.value); ok {
					return true, ver
				}
			}
		}
	}
	for _, mm := range e.metas {
		if content, ok := metas[mm.name]; ok {
			if ok2, ver := mm.pat.matchStr(content); ok2 {
				return true, ver
			}
		}
	}
	return false, ""
}

func extractMetas(body string) map[string]string {
	result := make(map[string]string)
	for _, m := range rMetaNC.FindAllStringSubmatch(body, -1) {
		if len(m) >= 3 {
			result[strings.ToLower(m[1])] = m[2]
		}
	}
	for _, m := range rMetaCN.FindAllStringSubmatch(body, -1) {
		if len(m) >= 3 {
			result[strings.ToLower(m[2])] = m[1]
		}
	}
	return result
}
