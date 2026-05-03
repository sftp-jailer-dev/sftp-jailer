package firewall

import (
	"regexp"
	"strings"
)

// AddedRule is a minimal typed shape for `ufw show added` lines. Only
// fields needed by SSHAllowPresent are decoded; CIDR + comment are
// deliberately discarded (the predicate is family-agnostic + comment-
// independent per FW-11 D-10).
type AddedRule struct {
	Action     string // "allow" / "deny" / "limit" / "reject"
	Proto      string // "tcp" / "udp" / "" (any)
	Port       string // "22" / "" (none, e.g. when AppProfile is set)
	AppProfile string // "OpenSSH" / "" (none)
	Raw        string // verbatim line, for debugging
}

// pendingFieldsRE collapses runs of whitespace when splitting tokens.
var pendingFieldsRE = regexp.MustCompile(`\s+`)

// ParseUFWShowAdded parses `ufw show added` stdout into AddedRule slices.
// The output starts with a header line "Added user rules (see 'ufw status'
// for running firewall):" then one rule per line. Format examples:
//
//	ufw allow 22/tcp
//	ufw allow 22
//	ufw allow OpenSSH
//	ufw allow proto tcp from 0.0.0.0/0 to any port 22 comment 'sftpj:v=1:user=alice'
//	ufw deny from 203.0.113.50
//
// Defensive: lines not starting with `ufw ` are skipped.
func ParseUFWShowAdded(out []byte) []AddedRule {
	var rules []AddedRule
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "ufw ") {
			continue
		}
		rules = append(rules, parseAddedLine(line))
	}
	return rules
}

// parseAddedLine extracts Action / Proto / Port / AppProfile from a
// single `ufw <action> ...` line. Anything past `comment '...'` is
// discarded (so an OpenSSH-named comment doesn't fool the AppProfile
// detection).
func parseAddedLine(line string) AddedRule {
	r := AddedRule{Raw: line}
	// Strip comment 'X' suffix before tokenizing.
	if idx := strings.Index(line, " comment "); idx >= 0 {
		line = line[:idx]
	}
	fields := pendingFieldsRE.Split(strings.TrimSpace(line), -1)
	if len(fields) < 3 || fields[0] != "ufw" {
		return r
	}
	r.Action = fields[1]
	// Look for keyword forms: "proto X", "port Y", or bare "PORT/PROTO" / "PORT" / "AppProfile".
	for i := 2; i < len(fields); i++ {
		f := fields[i]
		switch {
		case f == "proto" && i+1 < len(fields):
			r.Proto = fields[i+1]
			i++
		case f == "port" && i+1 < len(fields):
			r.Port = fields[i+1]
			i++
		case strings.Contains(f, "/"):
			// "22/tcp" form.
			parts := strings.SplitN(f, "/", 2)
			if isAllDigits(parts[0]) {
				r.Port = parts[0]
				r.Proto = parts[1]
			}
		case isAllDigits(f):
			// bare port, "22"
			if r.Port == "" {
				r.Port = f
			}
		case looksLikeAppProfile(f):
			// App profile names are capitalized, e.g. "OpenSSH".
			if r.AppProfile == "" && r.Port == "" {
				r.AppProfile = f
			}
		}
	}
	return r
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func looksLikeAppProfile(s string) bool {
	// App profiles are short, capitalized, alphanumeric; reject keyword
	// tokens like "from", "to", "any".
	switch s {
	case "from", "to", "any", "in", "out", "on":
		return false
	}
	if s == "" {
		return false
	}
	return s[0] >= 'A' && s[0] <= 'Z'
}

// SSHAllowPresent returns true if any rule matches the FW-11 D-10
// predicate: action=allow AND (port=22 AND proto in {tcp, ""}) OR
// (app=OpenSSH). Family-agnostic - both v4 and v6 rules satisfy.
func SSHAllowPresent(rules []AddedRule) bool {
	for _, r := range rules {
		if matchesSSHAllow(r) {
			return true
		}
	}
	return false
}

// SSHAllowMatchedAs returns "OpenSSH application profile" or "tcp/22"
// for the FIRST matching rule, or "" if no rule matches. Used to
// populate the modal's "SSH allow rule found: <matchedAs>" copy.
func SSHAllowMatchedAs(rules []AddedRule) string {
	for _, r := range rules {
		if r.Action != "allow" {
			continue
		}
		if r.AppProfile == "OpenSSH" {
			return "OpenSSH application profile"
		}
		if r.Port == "22" && (r.Proto == "tcp" || r.Proto == "") {
			return "tcp/22"
		}
	}
	return ""
}

func matchesSSHAllow(r AddedRule) bool {
	if r.Action != "allow" {
		return false
	}
	if r.AppProfile == "OpenSSH" {
		return true
	}
	if r.Port == "22" && (r.Proto == "tcp" || r.Proto == "") {
		return true
	}
	return false
}
