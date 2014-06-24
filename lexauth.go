package httpclient

import (
	"fmt"
	"github.com/jimrobinson/lexrec"
	"strings"
)

const (
	ItemIgnore lexrec.ItemType = lexrec.ItemEOF + 1 + iota
	ItemBasic
	ItemDigest
	ItemRealm
	ItemDomain
	ItemNonce
	ItemOpaque
	ItemStale
	ItemAlgorithm
	ItemQop
	ItemAuthParam
)

func itemName(t lexrec.ItemType) string {
	switch t {
	case lexrec.ItemError:
		return "ERROR"
	case lexrec.ItemEOF:
		return "EOF"
	case lexrec.ItemEOR:
		return "EOR"
	case ItemBasic:
		return "Basic"
	case ItemDigest:
		return "Digest"
	case ItemIgnore:
		return "ignore"
	case ItemRealm:
		return "realm"
	case ItemDomain:
		return "domain"
	case ItemNonce:
		return "nonce"
	case ItemOpaque:
		return "opaque"
	case ItemStale:
		return "stale"
	case ItemAlgorithm:
		return "algorithm"
	case ItemQop:
		return "qop"
	case ItemAuthParam:
		return "auth-param"
	default:
		return fmt.Sprintf("unknown ItemType %d", t)
	}
}

// separators per RFC 2616
var separators = `()<>@,;:\"/[]?={} ` + "\t"

// whitespace per RFC 2616
var whitespace = " \r\n\t"

// ctl are control characters per RFC 2616
var ctl = "\x00" +
	"\x01" +
	"\x02" +
	"\x03" +
	"\x04" +
	"\x05" +
	"\x06" +
	"\x07" +
	"\x08" +
	"\x09" +
	"\x0A" +
	"\x0B" +
	"\x0C" +
	"\x0D" +
	"\x0E" +
	"\x0F" +
	"\x10" +
	"\x11" +
	"\x12" +
	"\x13" +
	"\x14" +
	"\x15" +
	"\x16" +
	"\x17" +
	"\x18" +
	"\x19" +
	"\x1A" +
	"\x1B" +
	"\x1C" +
	"\x1D" +
	"\x1E" +
	"\x1F" +
	"\x7F"

// nontoken characters are separators, whitespace, and ctl
var nontoken = separators + whitespace + ctl

// emitWWWAuthenticate drives a lexer to parse an RFC 2617
// Basic or Digest authentication challenge
//
// The specification defines a Basic authentication challenge as:
//
// challenge         = "Basic" realm
//
// realm             = "realm" "=" realm-value
// realm-value       = quoted-string
//
// The specification defines a Digest authentication challenge as:
//
// challenge         =  "Digest" digest-challenge
//
// digest-challenge  = 1#( realm | [ domain ] | nonce | [ opaque ] |[ stale ]
//                          | [ algorithm ] | [ qop-options ] | [auth-param] )
//
// The BNF for these constructs:
//
//  domain            = "domain" "=" <"> URI ( 1*SP URI ) <">
//  URI               = absoluteURI | abs_path
//  nonce             = "nonce" "=" nonce-value
//  nonce-value       = quoted-string
//  opaque            = "opaque" "=" quoted-string
//  stale             = "stale" "=" ( "true" | "false" )
//  algorithm         = "algorithm" "=" ( "MD5" | "MD5-sess" | token )
//  qop-options       = "qop" "=" <"> 1#qop-value <">
//  qop-value         = "auth" | "auth-int" | token
//  auth-param        = token "=" ( token | quoted-string )
//
//  token             = 1*<any CHAR except CTLs or separators>
//  separators        = "(" | ")" | "<" | ">" | "@"
//                    | "," | ";" | ":" | "\" | <">
//                    | "/" | "[" | "]" | "?" | "="
//                    | "{" | "}" | SP | HT
//
//  quoted-string     = ( <"> *(qdtext | quoted-pair ) <"> )
//  qdtext            = <any TEXT except <">>
//  quoted-pair       = "\" CHAR
//
// An example challenge:
//
//   Digest realm="Sample Digest Realm",
//			nonce="nWjG15v1BAA=744a97693b14ea8805cadf32fcc3f57f245d08eb",
//			algorithm=MD5, domain="/", qop="auth"
//
func emitWWWAuthenticate(l *lexrec.Lexer) {
	defer l.Emit(lexrec.ItemEOF)

	if l.Peek() == lexrec.EOF {
		l.Errorf("emitWWWAuthenticate: expected token character, got EOF")
		return
	}

	if l.AcceptRun(whitespace) {
		l.Skip()
	}

	if !l.ExceptRun(nontoken) {
		l.Errorf("emitWWWAuthenticate: expected token character, got %q", l.Peek())
		return
	}

	for {
		if l.Peek() == lexrec.EOF {
			return
		}

		switch strings.ToLower(string(l.Bytes())) {
		case "basic":
			l.Emit(ItemBasic)

			if l.AcceptRun(whitespace) {
				l.Skip()
			} else {
				l.Errorf("expected whitespace after 'Basic', got %q", l.Peek())
				return
			}

			emitBasicParams(l)

		case "digest":
			l.Emit(ItemDigest)

			if l.AcceptRun(whitespace) {
				l.Skip()
			} else {
				l.Errorf("expected whitespace after 'Digest', got %q", l.Peek())
				return
			}

			emitDigestParams(l)

		default:
			advanceChallenge(l)
		}
	}
}

// advanceChallenge skips over an unrecognized WWW-Authenticate challenge.
func advanceChallenge(l *lexrec.Lexer) {
	if l.AcceptRun(whitespace) {
		l.Skip()
	}

	expectParam := true
	for expectParam {
		if l.ExceptRun(nontoken) {
			r := l.Peek()
			if r == '=' {
				l.Accept("=")
				l.Skip()
				if l.Peek() == '"' {
					if lexrec.Quote(l, ItemAuthParam, false) {
						l.Skip()
					}
				} else {
					if l.ExceptRun(nontoken) {
						l.Skip()
					} else {
						l.Errorf("advanceChallenge: expected a token character, got %q", l.Peek())
					}
				}
			} else if isSpace(r) {
				return
			} else {
				l.Errorf("advanceChallenge: expected either whitespace or '=', got %q", l.Peek())
				return
			}

			expectParam = advanceParam(l)
		} else {
			return
		}
	}
}

// emitBasicParams expects to be positioned at the start of the
// 'realm' Basic authentication parameter.
func emitBasicParams(l *lexrec.Lexer) {

	expectParam := true

	for expectParam {
		if !l.ExceptRun(nontoken) {
			l.Errorf("emitBasicParams: expected a token character, got %p", l.Peek())
			return
		}

		switch string(l.Bytes()) {
		case "realm":
			emitQuotedToken(l, ItemRealm)
		default:
			r := l.Peek()
			if r == ',' || isSpace(r) || r == lexrec.EOF {
				return
			}
			ignoreToken(l)
		}

		expectParam = advanceParam(l)
	}
}

// emitDigestParam expects to be positioned at the start of a Digest
// authentication parameter, <name>=<value>, where <name> is a valid
// token and where <value> is either a token or a quoted-string.
func emitDigestParams(l *lexrec.Lexer) {

	expectParam := true

	for expectParam {
		if !l.ExceptRun(nontoken) {
			l.Errorf("emitDigestParams: expected a token character, got %p", l.Peek())
			return
		}

		switch strings.ToLower(string(l.Bytes())) {
		case "realm":
			emitQuotedToken(l, ItemRealm)
		case "domain":
			emitQuotedToken(l, ItemDomain)
		case "nonce":
			emitQuotedToken(l, ItemNonce)
		case "opaque":
			emitQuotedToken(l, ItemOpaque)
		case "stale":
			emitBoolToken(l, ItemStale)
		case "algorithm":
			emitToken(l, ItemAlgorithm)
		case "qop":
			emitQuotedToken(l, ItemQop)
		default:
			r := l.Peek()
			if r == ',' || isSpace(r) || r == lexrec.EOF {
				return
			}
			ignoreToken(l)
		}

		expectParam = advanceParam(l)
	}
}

// emitQuotedToken transmits the quoted-string value from <name>=<value>
func emitQuotedToken(l *lexrec.Lexer, t lexrec.ItemType) {
	if !l.Accept("=") {
		l.Errorf("emitQuotedToken: expected '=' after '%s', got %q'", itemName(t), l.Peek())
		return
	}

	l.Skip()

	if !lexrec.Quote(l, t, true) {
		l.Errorf("emitToken: expected a quoted string after '%s=', got %q", itemName(t), l.Peek())
	}
}

// emitToken emits the token value from <name>=<value>
func emitToken(l *lexrec.Lexer, t lexrec.ItemType) {
	if !l.Accept("=") {
		l.Errorf("emitToken expected '=' after '%s', got %q'", itemName(t), l.Peek())
		return
	}

	l.Skip()

	if !l.ExceptRun(nontoken) {
		l.Errorf("emitToken expected a token character, got %q", l.Peek())
		return
	}

	l.Emit(t)
}

// emitBoolToken emits the token value from <name>=<value>, where the
// value is either "true" or "false" (case insensitive)
func emitBoolToken(l *lexrec.Lexer, t lexrec.ItemType) {
	if !l.Accept("=") {
		l.Errorf("emitBoolToken: expected '=' after '%s', got %q'", itemName(t), l.Peek())
		return
	}

	l.Skip()

	if !l.ExceptRun(nontoken) {
		l.Errorf("emitBoolToken: expected a token character, got %q", l.Peek())
		return
	}

	s := strings.ToLower(string(l.Bytes()))
	if s == "true" || s == "false" {
		l.Emit(t)
		return
	} else {
		l.Errorf("emitBoolToken: expected token to be 'true' or 'false', got %q", s)
	}
}

// ignoreToken skips past <name>=<value>, where the value may be a
// token or a quoted-string.
func ignoreToken(l *lexrec.Lexer) {

	p := string(l.Bytes())
	l.Skip()

	if !l.Accept("=") {
		l.Errorf("ignoreToken: after '%s' expected '=', got %q'", p, l.Peek())
		return
	} else {
		l.Skip()
	}

	if l.Peek() == '"' {
		if lexrec.Quote(l, ItemAuthParam, false) {
			l.Skip()
		}
	} else {
		if l.ExceptRun(nontoken) {
			l.Skip()
		} else {
			l.Errorf("ignoreToken: expected a token character, got %q", l.Peek())
		}
	}
}

// advanceParam attempts to advance to the start of the next
// parameter and returns true if the advance succeeded, otherwise
// false if the lexer is at EOF or if unexpected characters were
// found.
func advanceParam(l *lexrec.Lexer) bool {
	if l.Peek() == lexrec.EOF {
		return false
	}

	l.AcceptRun(whitespace)

	if l.Next() != ',' {
		l.Errorf("advanceParam: expected comma, got %q", l.Peek())
		return false
	}

	l.AcceptRun(whitespace)

	l.Skip()

	return true
}

// isSpace tests if r is within the string whitespace
func isSpace(r rune) bool {
	return strings.ContainsRune(whitespace, r)
}
