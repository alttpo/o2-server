package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"net"
)

// Group passwords (protocol 0x05).
//
// A password keeps uninvited players out of a group; it isn't meant to hold up against someone who can see the
// network's packets. The client never sends the password itself but a token made from it:
//
//	token = SHA-256("o2-p5-group:" || password)       (32 bytes)
//
// carried in the optional auth field at the end of join-group (u8 length, then the token). The first player to
// join a group that doesn't exist sets the group's password by joining with a token; the server keeps it for as long
// as the group lives. Every later join of that group must carry the same token. A join without a token creates and
// joins a group without a password, and anyone can join that.
//
// A client that is already in the group under the same session and address doesn't need the token to be checked again
// when it resends its join-group. Joins refused for the password get a join-nak with a reason below and no body.

// join-nak reasons of group passwords:
const (
	// P5NakAuthRequired: the group has a password and the join had no token.
	P5NakAuthRequired = 2
	// P5NakAuthFailed: the token isn't the group's.
	P5NakAuthFailed = 3
	// P5NakAuthUnexpected: the group exists without a password, so the token can't be used; or the field is malformed.
	P5NakAuthUnexpected = 4
)

const p5AuthTokenSize = sha256.Size

// P5AuthToken makes the token of a password.
func P5AuthToken(password string) []byte {
	sum := sha256.Sum256([]byte("o2-p5-group:" + password))
	return sum[:]
}

var p5AuthNakText = map[uint8]string{
	P5NakAuthRequired:   "password required, none given",
	P5NakAuthFailed:     "wrong password",
	P5NakAuthUnexpected: "group has no password, or the password field is malformed",
}

func (s *p5Server) sendAuthNak(addr *net.UDPAddr, groupKey string, reason uint8) {
	log.Printf("p5: [group %s] (%v) join refused: %s\n", groupKey, addr, p5AuthNakText[reason])
	s.sendTo(addr, append(p5Packet(P5JoinNak, 1), reason))
}

// authorize decides whether a join-group may enter the group; if not, it has sent the nak. token is the password
// to give the group if the join creates it.
func (s *p5Server) authorize(addr *net.UDPAddr, j *P5Join, groupKey string) (ok bool, token []byte) {
	if len(j.Auth) != 0 && len(j.Auth) != p5AuthTokenSize {
		s.sendAuthNak(addr, groupKey, P5NakAuthUnexpected)
		return false, nil
	}
	g := s.groups[groupKey]
	if g == nil {
		return true, j.Auth
	}
	switch {
	case g.AuthToken == nil && len(j.Auth) != 0:
		s.sendAuthNak(addr, groupKey, P5NakAuthUnexpected)
	case g.AuthToken == nil:
		return true, nil
	case len(j.Auth) == 0:
		s.sendAuthNak(addr, groupKey, P5NakAuthRequired)
	case subtle.ConstantTimeCompare(g.AuthToken, j.Auth) != 1:
		s.sendAuthNak(addr, groupKey, P5NakAuthFailed)
	default:
		return true, nil
	}
	return false, nil
}
