package main

import (
	"encoding/hex"
	"testing"
	"time"
)

func (h *p5Harness) joinAuth(from int, seq uint8, session uint64, group string, auth []byte) {
	b, err := AppendP5Join(nil, &P5Join{JoinSeq: seq, SessionID: session, Group: group, Name: "n", Info: []byte{2, 0}, Auth: auth})
	if err != nil {
		h.t.Fatal(err)
	}
	h.recv(from, P5JoinGroup, b)
}

// nak takes the one join-nak sent to n and returns its reason.
func (h *p5Harness) nak(n int) uint8 {
	naks := h.take(n, P5JoinNak)
	if len(naks) != 1 || len(naks[0]) != 1 {
		h.t.Fatalf("client %d: want 1 join-nak, got %d", n, len(naks))
	}
	return naks[0][0]
}

// the same vector as o2's client/protocol05/auth_test.go:
func TestP5AuthTokenVector(t *testing.T) {
	if got := hex.EncodeToString(P5AuthToken("hunter2")); got != "151ea7df512994f88ab9a1389a87f50c0bec6135cf0042fe1ad6ede592d03456" {
		t.Fatalf("token %s", got)
	}
}

func TestP5Password(t *testing.T) {
	h := newP5Harness(t)
	pw := P5AuthToken("hunter2")

	// the first player sets the password and joins:
	h.joinAuth(1, 1, 100, "Secret", pw)
	if i := h.joinAckIndex(1); i != 0 {
		t.Fatalf("creator index %d", i)
	}
	// its resent join is idempotent:
	h.joinAuth(1, 1, 100, "Secret", pw)
	h.joinAckIndex(1)

	h.join(2, 1, 200, "secret", "bob")
	if r := h.nak(2); r != P5NakAuthRequired {
		t.Fatalf("no token: %d", r)
	}
	h.joinAuth(2, 1, 200, "secret", P5AuthToken("wrong"))
	if r := h.nak(2); r != P5NakAuthFailed {
		t.Fatalf("wrong token: %d", r)
	}
	h.joinAuth(2, 1, 200, "secret", []byte{1, 2, 3})
	if r := h.nak(2); r != P5NakAuthUnexpected {
		t.Fatalf("malformed token: %d", r)
	}
	if len(h.s.byAddr) != 1 {
		t.Fatalf("a refused join got in")
	}

	h.joinAuth(2, 1, 200, "secret", pw)
	if i := h.joinAckIndex(2); i != 1 {
		t.Fatalf("bob index %d", i)
	}
	// moving to another group needs that group's password too:
	h.joinAuth(2, 2, 200, "other", pw)
	if i := h.joinAckIndex(2); i != 0 {
		t.Fatalf("bob in the new group: %d", i)
	}
	h.join(1, 2, 100, "other", "alice")
	if r := h.nak(1); r != P5NakAuthRequired {
		t.Fatalf("moving into a protected group: %d", r)
	}
}

func TestP5PasswordOptional(t *testing.T) {
	h := newP5Harness(t)

	// a group without a password takes anyone, and can't get one later:
	h.join(1, 1, 100, "open", "alice")
	h.joinAckIndex(1)
	h.joinAuth(2, 1, 200, "open", P5AuthToken("pw"))
	if r := h.nak(2); r != P5NakAuthUnexpected {
		t.Fatalf("token on an open group: %d", r)
	}
	h.join(2, 1, 200, "open", "bob")
	h.joinAckIndex(2)

	// the password goes with the group:
	h2 := newP5Harness(t)
	h2.joinAuth(1, 1, 100, "g", P5AuthToken("pw"))
	h2.joinAckIndex(1)
	h2.recv(1, P5LeaveGroup, nil)
	h2.now = h2.now.Add(time.Minute)
	h2.s.expire()
	if len(h2.s.groups) != 0 {
		t.Fatalf("group kept")
	}
	h2.join(2, 1, 200, "g", "carol")
	h2.joinAckIndex(2)
}
