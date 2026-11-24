package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

type p5Sent struct {
	to  string
	pkt []byte
}

type p5Harness struct {
	t    *testing.T
	s    *p5Server
	now  time.Time
	sent []p5Sent
}

func newP5Harness(t *testing.T) *p5Harness {
	h := &p5Harness{t: t, now: time.Unix(1700000000, 0)}
	h.s = newP5Server()
	h.s.now = func() time.Time { return h.now }
	h.s.send = func(addr *net.UDPAddr, pkt []byte) error {
		h.sent = append(h.sent, p5Sent{to: addr.String(), pkt: append([]byte(nil), pkt...)})
		return nil
	}
	return h
}

func p5Addr(n int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(10, 0, 0, byte(n)), Port: 5000 + n}
}

func (h *p5Harness) recv(from int, kind P5Kind, body []byte) {
	h.s.handle(p5Addr(from), append([]byte{uint8(kind)}, body...))
}

func (h *p5Harness) join(from int, seq uint8, session uint64, group, name string) {
	b, err := AppendP5Join(nil, &P5Join{JoinSeq: seq, SessionID: session, Group: group, Name: name, Info: []byte{2, 0}})
	if err != nil {
		h.t.Fatal(err)
	}
	h.recv(from, P5JoinGroup, b)
}

// take returns and forgets the bodies (after the kind byte) of the packets of kind sent to client n.
func (h *p5Harness) take(n int, kind P5Kind) (bodies [][]byte) {
	to := p5Addr(n).String()
	kept := h.sent[:0]
	for _, p := range h.sent {
		if p.to == to && P5Kind(p.pkt[3]) == kind {
			if binary.LittleEndian.Uint16(p.pkt) != 25887 || p.pkt[2] != p5Protocol {
				h.t.Fatalf("bad header % x", p.pkt[:4])
			}
			bodies = append(bodies, p.pkt[4:])
			continue
		}
		kept = append(kept, p)
	}
	h.sent = kept
	return
}

func (h *p5Harness) clear() { h.sent = nil }

func (h *p5Harness) joinAckIndex(n int) int {
	acks := h.take(n, P5JoinAck)
	if len(acks) != 1 {
		h.t.Fatalf("client %d: want 1 join-ack, got %d", n, len(acks))
	}
	return int(binary.LittleEndian.Uint16(acks[0][1:]))
}

type p5InfoEntry struct {
	index uint16
	name  string
}

func p5ParsePlayerInfo(bodies [][]byte) (es []p5InfoEntry) {
	for _, b := range bodies {
		r := &p5Reader{b: b}
		for len(r.b) > 0 {
			idx := r.u16()
			name := string(r.tiny())
			r.tiny()
			es = append(es, p5InfoEntry{idx, name})
		}
	}
	return
}

func TestP5JoinAckAndRoster(t *testing.T) {
	h := newP5Harness(t)
	h.join(1, 1, 100, "Group", "alice")
	if i := h.joinAckIndex(1); i != 0 {
		t.Fatalf("alice index %d", i)
	}
	if es := p5ParsePlayerInfo(h.take(1, P5PlayerInfo)); len(es) != 1 || es[0].name != "alice" {
		t.Fatalf("alice roster %+v", es)
	}

	h.join(2, 1, 200, " group ", "bob")
	if i := h.joinAckIndex(2); i != 1 {
		t.Fatalf("bob index %d", i)
	}
	if es := p5ParsePlayerInfo(h.take(1, P5PlayerInfo)); len(es) != 1 || es[0] != (p5InfoEntry{1, "bob"}) {
		t.Fatalf("alice told %+v", es)
	}
	if es := p5ParsePlayerInfo(h.take(2, P5PlayerInfo)); len(es) != 2 || es[0].name != "alice" || es[1].name != "bob" {
		t.Fatalf("bob roster %+v", es)
	}

	// the join-ack carries the seq and the server time:
	h.join(2, 1, 200, "group", "bob")
	acks := h.take(2, P5JoinAck)
	if len(acks) != 1 || acks[0][0] != 1 || int64(binary.LittleEndian.Uint64(acks[0][3:])) != h.now.UnixNano() {
		t.Fatalf("idempotent ack % x", acks)
	}
	// nothing changed, so alice isn't told again:
	if es := h.take(1, P5PlayerInfo); len(es) != 0 {
		t.Fatalf("alice told again")
	}

	// a rename goes to the others:
	h.join(2, 2, 200, "group", "robert")
	if i := h.joinAckIndex(2); i != 1 {
		t.Fatalf("rename moved index to %d", i)
	}
	if es := p5ParsePlayerInfo(h.take(1, P5PlayerInfo)); len(es) != 1 || es[0].name != "robert" {
		t.Fatalf("rename %+v", es)
	}

	// a delayed older join is ignored:
	h.clear()
	h.join(2, 1, 200, "other", "bob")
	if len(h.sent) != 0 {
		t.Fatalf("stale join answered: %d packets", len(h.sent))
	}
	if ref := h.s.byAddr[p5ClientKey(p5Addr(2))]; ref.groupKey != "group" {
		t.Fatalf("stale join moved bob to %q", ref.groupKey)
	}
}

func TestP5NakAndLeave(t *testing.T) {
	h := newP5Harness(t)
	h.recv(9, P5BroadcastAll, []byte{1, 2, 3})
	naks := h.take(9, P5JoinNak)
	if len(naks) != 1 || naks[0][0] != P5NakNotJoined {
		t.Fatalf("naks % x", naks)
	}
	// leave-group and server kinds from an unknown address get no nak:
	h.recv(9, P5LeaveGroup, nil)
	h.recv(9, P5RelayAll, nil)
	if len(h.sent) != 0 {
		t.Fatalf("unexpected %d packets", len(h.sent))
	}

	h.join(1, 1, 100, "g", "a")
	h.join(2, 1, 200, "g", "b")
	h.clear()
	h.recv(1, P5LeaveGroup, nil)
	left := h.take(2, P5PlayerLeft)
	if len(left) != 1 || binary.LittleEndian.Uint16(left[0]) != 0 || left[0][2] != P5LeftLeft {
		t.Fatalf("left % x", left)
	}
	h.recv(1, P5Echo, make([]byte, 8))
	if len(h.take(1, P5JoinNak)) != 1 {
		t.Fatalf("no nak after leave")
	}
}

func TestP5MoveGroup(t *testing.T) {
	h := newP5Harness(t)
	h.join(1, 1, 100, "g1", "a")
	h.join(2, 1, 200, "g1", "b")
	h.clear()
	h.join(1, 2, 100, "g2", "a")
	left := h.take(2, P5PlayerLeft)
	if len(left) != 1 || left[0][2] != P5LeftMoved {
		t.Fatalf("left % x", left)
	}
	if i := h.joinAckIndex(1); i != 0 {
		t.Fatalf("index in g2 %d", i)
	}
	// broadcasts now go to g2 only:
	h.recv(1, P5BroadcastAll, []byte{7})
	if n := len(h.take(2, P5RelayAll)); n != 0 {
		t.Fatalf("b got %d relays from g2", n)
	}
}

func TestP5GraceAndRetake(t *testing.T) {
	h := newP5Harness(t)
	h.join(1, 1, 100, "g", "a")
	h.join(2, 1, 200, "g", "b")
	h.recv(1, P5LeaveGroup, nil)
	h.clear()

	// index 0 is reserved for a's session:
	h.join(3, 1, 300, "g", "c")
	if i := h.joinAckIndex(3); i != 2 {
		t.Fatalf("c index %d", i)
	}
	// a's session takes its slot back, even from another address:
	h.join(4, 1, 100, "g", "a")
	if i := h.joinAckIndex(4); i != 0 {
		t.Fatalf("a retake index %d", i)
	}
	if es := p5ParsePlayerInfo(h.take(2, P5PlayerInfo)); len(es) != 2 || es[1] != (p5InfoEntry{0, "a"}) {
		t.Fatalf("b told %+v", es)
	}

	// after the grace period, the slot goes to anyone:
	h.recv(4, P5LeaveGroup, nil)
	h.now = h.now.Add(h.s.slotGrace)
	h.join(5, 1, 500, "g", "d")
	if i := h.joinAckIndex(5); i != 0 {
		t.Fatalf("d index %d", i)
	}
}

func TestP5Migrate(t *testing.T) {
	h := newP5Harness(t)
	h.join(1, 1, 100, "g", "a")
	h.join(2, 1, 200, "g", "b")
	h.recv(1, P5JoinSector, []byte{1, 0x34, 0x12, 0, 0})
	h.clear()

	// a's NAT rebinds: same session from a new address keeps its index and sector, and b sees nothing:
	h.join(3, 1, 100, "g", "a")
	if i := h.joinAckIndex(3); i != 0 {
		t.Fatalf("migrated index %d", i)
	}
	if n := len(h.take(2, P5PlayerLeft)) + len(h.take(2, P5PlayerInfo)); n != 0 {
		t.Fatalf("b told %d things", n)
	}
	h.recv(2, P5BroadcastSector, []byte{0x34, 0x12, 0, 0, 9})
	if n := len(h.take(3, P5RelaySector)); n != 1 {
		t.Fatalf("migrated sector lost: %d relays", n)
	}
	h.recv(1, P5Echo, make([]byte, 8))
	if len(h.take(1, P5JoinNak)) != 1 {
		t.Fatalf("old address still joined")
	}
}

func TestP5SectorsAndRelays(t *testing.T) {
	h := newP5Harness(t)
	h.join(1, 1, 100, "g", "a")
	h.join(2, 1, 200, "g", "b")
	h.join(3, 1, 300, "g", "c")
	h.clear()

	sector := func(n int, seq uint8, s uint32) {
		h.recv(n, P5JoinSector, binary.LittleEndian.AppendUint32([]byte{seq}, s))
	}
	sector(2, 1, 0x1234)
	sector(3, 1, 0x5678)
	if acks := h.take(2, P5SectorAck); len(acks) != 1 || acks[0][0] != 1 {
		t.Fatalf("sector ack % x", acks)
	}

	h.now = time.UnixMilli(0x123456789)
	h.recv(1, P5BroadcastSector, []byte{0x34, 0x12, 0, 0, 0xAA, 0xBB})
	rs := h.take(2, P5RelaySector)
	if len(rs) != 1 || !bytes.Equal(rs[0], []byte{0, 0, 0x89, 0x67, 0x34, 0x12, 0, 0, 0xAA, 0xBB}) {
		t.Fatalf("relay-sector % x", rs)
	}
	if n := len(h.take(3, P5RelaySector)) + len(h.take(1, P5RelaySector)); n != 0 {
		t.Fatalf("relay-sector went to %d others", n)
	}

	// a stale join-sector is acked but not applied:
	sector(2, 0, 0x5678)
	if acks := h.take(2, P5SectorAck); len(acks) != 1 || acks[0][0] != 0 {
		t.Fatalf("stale ack % x", acks)
	}
	h.recv(1, P5BroadcastSector, []byte{0x34, 0x12, 0, 0})
	if n := len(h.take(2, P5RelaySector)); n != 1 {
		t.Fatalf("stale join-sector applied")
	}

	// leave-sector:
	h.recv(2, P5LeaveSector, []byte{2})
	h.recv(1, P5BroadcastSector, []byte{0x34, 0x12, 0, 0})
	if n := len(h.take(2, P5RelaySector)); n != 0 {
		t.Fatalf("relay after leave-sector")
	}

	// relay-all goes to everyone but the sender:
	h.recv(1, P5BroadcastAll, []byte{5})
	ra := h.take(2, P5RelayAll)
	if len(ra) != 1 || !bytes.Equal(ra[0], []byte{0, 0, 0x89, 0x67, 5}) || len(h.take(3, P5RelayAll)) != 1 ||
		len(h.take(1, P5RelayAll)) != 0 {
		t.Fatalf("relay-all % x", ra)
	}

	// echo:
	h.recv(1, P5Echo, binary.LittleEndian.AppendUint64(nil, 42))
	er := h.take(1, P5EchoReply)
	if len(er) != 1 || binary.LittleEndian.Uint64(er[0]) != 42 ||
		int64(binary.LittleEndian.Uint64(er[0][8:])) != h.now.UnixNano() {
		t.Fatalf("echo % x", er)
	}
}

func TestP5WhoIs(t *testing.T) {
	h := newP5Harness(t)
	h.join(1, 1, 100, "g", "a")
	h.join(2, 1, 200, "g", "b")
	h.clear()
	h.recv(1, P5WhoIs, []byte{1, 0, 7, 0, 0, 0})
	es := p5ParsePlayerInfo(h.take(1, P5PlayerInfo))
	if len(es) != 2 || es[0] != (p5InfoEntry{1, "b"}) || es[1] != (p5InfoEntry{0, "a"}) {
		t.Fatalf("who-is %+v", es)
	}
}

func TestP5Expiry(t *testing.T) {
	h := newP5Harness(t)
	h.join(1, 1, 100, "g", "a")
	h.join(2, 1, 200, "g", "b")
	h.now = h.now.Add(10 * time.Second)
	h.recv(2, P5Echo, make([]byte, 8))
	h.clear()
	h.now = h.now.Add(6 * time.Second)
	h.s.expire()
	left := h.take(2, P5PlayerLeft)
	if len(left) != 1 || left[0][2] != P5LeftTimedOut {
		t.Fatalf("left % x", left)
	}
	h.now = h.now.Add(30 * time.Second)
	h.s.expire()
	h.now = h.now.Add(h.s.slotGrace)
	h.s.expire()
	if len(h.s.groups) != 0 || len(h.s.byAddr) != 0 {
		t.Fatalf("groups %d clients %d", len(h.s.groups), len(h.s.byAddr))
	}
}

func p5FactPutBody(factNum uint8, size int, chunk int, data []byte) []byte {
	b := []byte{factNum}
	b = binary.LittleEndian.AppendUint32(b, uint32(size))
	b = append(b, uint8(chunk))
	return append(b, data...)
}

func (h *p5Harness) upload(n int, factNum uint8, fact []byte) {
	for i := 0; i < p5ChunkCount(len(fact)); i++ {
		o := i * p5FactChunkSize
		h.recv(n, P5FactPut, p5FactPutBody(factNum, len(fact), i, fact[o:o+p5ChunkLen(len(fact), i)]))
	}
}

func TestP5Facts(t *testing.T) {
	h := newP5Harness(t)
	h.join(1, 1, 100, "g", "a")
	h.join(2, 1, 200, "g", "b")
	h.clear()

	fact := make([]byte, 2500)
	for i := range fact {
		fact[i] = byte(i * 7)
	}
	sum := sha256.Sum256(fact)

	// chunks out of order and repeated:
	h.recv(1, P5FactPut, p5FactPutBody(3, 2500, 2, fact[2048:]))
	h.recv(1, P5FactPut, p5FactPutBody(3, 2500, 2, fact[2048:]))
	h.recv(1, P5FactPut, p5FactPutBody(3, 2500, 0, fact[:1024]))
	st := h.take(1, P5FactStatus)
	if len(st) != 3 || st[2][1] != P5FactReceiving || binary.LittleEndian.Uint64(st[2][2:]) != 0b101 {
		t.Fatalf("status % x", st)
	}
	if len(h.take(2, P5FactList)) != 0 {
		t.Fatalf("fact-list before complete")
	}
	// a chunk of the wrong length is rejected:
	h.recv(1, P5FactPut, p5FactPutBody(3, 2500, 1, fact[1024:2000]))
	if st := h.take(1, P5FactStatus); len(st) != 1 || st[0][1] != P5FactRejected {
		t.Fatalf("short chunk % x", st)
	}
	h.recv(1, P5FactPut, p5FactPutBody(3, 2500, 1, fact[1024:2048]))
	st = h.take(1, P5FactStatus)
	if len(st) != 1 || st[0][1] != P5FactComplete || binary.LittleEndian.Uint64(st[0][2:]) != 0b111 {
		t.Fatalf("complete % x", st)
	}
	wantList := append([]byte{0, 0, 3, 0xC4, 0x09, 0, 0}, sum[:p5HashSize]...)
	for _, n := range []int{1, 2} {
		if fl := h.take(n, P5FactList); len(fl) != 1 || !bytes.Equal(fl[0], wantList) {
			t.Fatalf("client %d fact-list % x", n, fl)
		}
	}

	// the fact is immutable:
	h.recv(1, P5FactPut, p5FactPutBody(3, 2500, 0, fact[:1024]))
	if st := h.take(1, P5FactStatus); len(st) != 1 || st[0][1] != P5FactComplete {
		t.Fatalf("re-put % x", st)
	}
	h.recv(1, P5FactPut, p5FactPutBody(3, 100, 0, fact[:100]))
	if st := h.take(1, P5FactStatus); len(st) != 1 || st[0][1] != P5FactRejected {
		t.Fatalf("resize % x", st)
	}

	// fact-get: chunks 0 and 2, plus a request for a fact that doesn't exist:
	get := binary.LittleEndian.AppendUint16(nil, 0)
	get = append(get, 3)
	get = binary.LittleEndian.AppendUint64(get, 0b101|1<<40)
	get = binary.LittleEndian.AppendUint16(get, 0)
	get = append(get, 9)
	get = binary.LittleEndian.AppendUint64(get, 1)
	h.recv(2, P5FactGet, get)
	fd := h.take(2, P5FactData)
	if len(fd) != 2 || !bytes.Equal(fd[0][4:], fact[:1024]) || fd[1][3] != 2 || !bytes.Equal(fd[1][4:], fact[2048:]) {
		t.Fatalf("fact-data %d packets", len(fd))
	}

	// b uploads the same bytes; they are stored once:
	h.upload(2, 0, fact)
	if len(h.s.blobs) != 1 || h.s.blobs[[p5HashSize]byte(sum[:p5HashSize])].refs != 2 {
		t.Fatalf("blobs %d", len(h.s.blobs))
	}

	// a leaves for longer than the grace period and comes back with the same session: its facts are still there, in
	// its own roster:
	h.recv(1, P5LeaveGroup, nil)
	h.now = h.now.Add(h.s.slotGrace)
	h.s.expire()
	h.clear()
	h.join(1, 2, 100, "g", "a")
	idx := h.joinAckIndex(1)
	var mine bool
	for _, fl := range h.take(1, P5FactList) {
		if int(binary.LittleEndian.Uint16(fl)) == idx && bytes.Equal(fl[2:], wantList[2:]) {
			mine = true
		}
	}
	if !mine {
		t.Fatalf("rejoined a's facts missing")
	}
	h.recv(1, P5FactPut, p5FactPutBody(3, 2500, 0, fact[:1024]))
	if st := h.take(1, P5FactStatus); len(st) != 1 || st[0][1] != P5FactComplete {
		t.Fatalf("rejoined re-put % x", st)
	}

	// the group's end frees the bytes:
	h.now = h.now.Add(time.Minute)
	h.s.expire()
	h.now = h.now.Add(h.s.slotGrace)
	h.s.expire()
	if len(h.s.groups) != 0 || len(h.s.blobs) != 0 {
		t.Fatalf("groups %d blobs %d", len(h.s.groups), len(h.s.blobs))
	}
}

func TestP5FactQuota(t *testing.T) {
	h := newP5Harness(t)
	h.s.sessionQuota = 3000
	h.join(1, 1, 100, "g", "a")
	h.clear()
	h.upload(1, 0, make([]byte, 2000))
	h.recv(1, P5FactPut, p5FactPutBody(1, 2000, 0, make([]byte, 1024)))
	st := h.take(1, P5FactStatus)
	if last := st[len(st)-1]; last[0] != 1 || last[1] != P5FactRejected {
		t.Fatalf("quota % x", last)
	}
	// too large and empty facts:
	h.recv(1, P5FactPut, p5FactPutBody(2, p5FactMaxSize+1, 0, make([]byte, 1024)))
	h.recv(1, P5FactPut, p5FactPutBody(2, 0, 0, nil))
	for _, s := range h.take(1, P5FactStatus) {
		if s[1] != P5FactRejected {
			t.Fatalf("bad size accepted % x", s)
		}
	}
}

func TestP5MaxSizeFact(t *testing.T) {
	h := newP5Harness(t)
	h.join(1, 1, 100, "g", "a")
	fact := bytes.Repeat([]byte{0x5A}, p5FactMaxSize)
	h.upload(1, 255, fact)
	st := h.take(1, P5FactStatus)
	if last := st[len(st)-1]; last[1] != P5FactComplete || binary.LittleEndian.Uint64(last[2:]) != ^uint64(0) {
		t.Fatalf("max fact % x", last)
	}
}

func TestP5JoinDecode(t *testing.T) {
	j := P5Join{JoinSeq: 9, SessionID: 0x1122334455667788, Group: "grp", Name: "nm", Info: []byte{2, 1}}
	b, err := AppendP5Join(nil, &j)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p5DecodeJoin(b)
	if err != nil || got.JoinSeq != 9 || got.SessionID != j.SessionID || got.Group != "grp" || got.Name != "nm" ||
		!bytes.Equal(got.Info, j.Info) {
		t.Fatalf("decode %+v %v", got, err)
	}
	if _, err := p5DecodeJoin(b[:len(b)-1]); err == nil {
		t.Fatalf("truncated join decoded")
	}
}
