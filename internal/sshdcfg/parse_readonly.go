// Package sshdcfg is the read-side parser for sshd_config drop-in files.
//
// Phase 1 is read-only: it detects whether /etc/ssh/sshd_config.d/ contains
// a drop-in with a "Match Group sftp-jailer" block + the expected chroot
// directives. Phase 3 will extend the package with a writer that preserves
// original formatting (each Directive already carries its RawLine for that
// purpose).
//
// No `Include` globbing: the doctor detector enumerates drop-ins via
// sysops.Glob directly; resolving Includes from the main sshd_config file
// is a Phase 3 concern.
package sshdcfg

import (
	"bufio"
	"bytes"
	"strings"
)

// DropIn is the parsed form of a single sshd drop-in file. Phase 1 is
// read-only; Phase 3 extends with a writer that reconstructs bytes from the
// preserved RawLine values.
type DropIn struct {
	// Directives are the top-level directives before the first Match block.
	Directives []Directive
	// Matches are Match blocks in file order.
	Matches []MatchBlock
	// Size is the original byte count parsed (useful for debugging).
	Size int
}

// Directive is a single sshd_config line that is not a comment, blank, or
// Match header. Keyword is lowercased (sshd is case-insensitive on keywords);
// Value is the remainder of the line after the keyword, trimmed.
type Directive struct {
	Keyword string // canonical lowercase
	Value   string // trimmed remainder after the keyword
	RawLine string // original line for byte-identity writeback (Phase 3)
	Line    int    // 1-based line number
}

// MatchBlock groups the Directive lines that follow a `Match ...` header
// until the next Match or end-of-file.
type MatchBlock struct {
	Condition string      // the text after "Match ", e.g. "Group sftp-jailer"
	Body      []Directive // directives inside this block
	Line      int         // 1-based line of the Match header itself
}

// ParseDropIn parses a single drop-in file. The current implementation never
// returns a non-nil error (the input is already in memory), but the signature
// reserves error for future extensions — e.g. a strict mode that rejects
// unknown directives.
func ParseDropIn(b []byte) (DropIn, error) {
	d := DropIn{Size: len(b)}
	sc := bufio.NewScanner(bytes.NewReader(b))
	// sshd_config lines can be long (e.g. a key list); grow the buffer so
	// we don't truncate on realistic inputs.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNo := 0
	var current *MatchBlock

	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		keyword := strings.ToLower(fields[0])

		// Value is the trimmed remainder of the line after the first
		// whitespace-delimited field — we take it from the trimmed line so
		// indentation is not preserved in Value (RawLine still carries it).
		value := ""
		if idx := indexFirstSpace(trimmed); idx > 0 && idx < len(trimmed) {
			value = strings.TrimSpace(trimmed[idx:])
		}

		dir := Directive{
			Keyword: keyword,
			Value:   value,
			RawLine: raw,
			Line:    lineNo,
		}

		if keyword == "match" {
			// Close the currently-open block (if any) and start a new one.
			if current != nil {
				d.Matches = append(d.Matches, *current)
			}
			current = &MatchBlock{Condition: value, Line: lineNo}
			continue
		}

		if current != nil {
			current.Body = append(current.Body, dir)
		} else {
			d.Directives = append(d.Directives, dir)
		}
	}
	if current != nil {
		d.Matches = append(d.Matches, *current)
	}
	return d, sc.Err()
}

// HasMatchGroup reports whether this drop-in contains a Match block whose
// condition starts with "Group <name>". The keyword comparison ("group") is
// case-insensitive; the group-name comparison is case-sensitive because
// unix group names are case-sensitive.
func (d DropIn) HasMatchGroup(name string) bool {
	for _, m := range d.Matches {
		fields := strings.Fields(m.Condition)
		if len(fields) < 2 {
			continue
		}
		if strings.EqualFold(fields[0], "Group") && fields[1] == name {
			return true
		}
	}
	return false
}

// GetDirective returns the first top-level occurrence of keyword
// (case-insensitive) and true; or a zero Directive and false if not present.
// Directives inside a Match block are NOT searched — iterate MatchBlock.Body
// for that.
func (d DropIn) GetDirective(keyword string) (Directive, bool) {
	lc := strings.ToLower(keyword)
	for _, dir := range d.Directives {
		if dir.Keyword == lc {
			return dir, true
		}
	}
	return Directive{}, false
}

// indexFirstSpace returns the index of the first ASCII space or tab in s,
// or -1 if none. Used to split keyword from value on the first whitespace
// run while keeping the rest of the line intact (multi-word values like
// "internal-sftp -f AUTHPRIV -l INFO" must round-trip unchanged).
func indexFirstSpace(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return i
		}
	}
	return -1
}
