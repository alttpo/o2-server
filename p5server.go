package main

import (
	"crypto/sha256"
	"encoding/binary"
	"log"
	"net"
	"time"
)

// p5Server holds every protocol 0x05 group and client; see PROTOCOL05.md. It is separate from the p1-p4 state, so p5
// clients never see older clients. It is only used from the main event loop.
type p5Server struct {
	groups map[string]*p5Group
	byAddr map[ClientKey]p5Ref
	blobs  map[[p5HashSize]byte]*p5Blob

	now  func() time.Time
	send func(addr *net.UDPAddr, pkt []byte) error

	disconnectTimeout time.Duration
	slotGrace         time.Duration
	sessionQuota      int
	groupQuota        int
	// maxSlots is the most slots (live and reserved) a group can have:
	maxSlots int
}

type p5Ref struct {
	groupKey string
	index    uint16
}

type p5SlotState uint8

const (
	p5SlotFree = p5SlotState(iota)
	p5SlotLive
	p5SlotGrace
)

type p5Slot struct {
	State p5SlotState

	Addr      net.UDPAddr
	Key       ClientKey
	SessionID uint64
	JoinSeq   uint8

	Name string
	Info []byte

	InSector  bool
	Sector    uint32
	SectorSeq uint8
	// SectorSeqSet is false until the first join-sector or leave-sector:
	SectorSeqSet bool

	LastSeen   time.Time
	GraceUntil time.Time
}

type p5Group struct {
	Key string
	// metrics identifies the group to the metrics reporters:
	metrics *ClientGroup
	Slots   []p5Slot
	// facts of each session that joined the group, kept as long as the group lives:
	Sessions  map[uint64]*p5Session
	FactBytes int
}

type p5Session struct {
	Facts [256]*p5Fact
	Bytes int
}

type p5Fact struct {
	Size     int
	Received uint64
	// buf is the fact being received; nil once complete:
	buf []byte

	Complete bool
	Hash     [p5HashSize]byte
	// Data is the shared copy of the complete fact's bytes:
	Data []byte
}

// p5Blob is the one copy of a fact's bytes shared by every fact with that hash:
type p5Blob struct {
	data []byte
	refs int
}

func newP5Server() *p5Server {
	return &p5Server{
		groups:            make(map[string]*p5Group),
		byAddr:            make(map[ClientKey]p5Ref),
		blobs:             make(map[[p5HashSize]byte]*p5Blob),
		now:               time.Now,
		disconnectTimeout: disconnectTimeout,
		slotGrace:         10 * time.Second,
		sessionQuota:      1 << 20,
		groupQuota:        16 << 20,
		maxSlots:          65536,
	}
}

func p5ClientKey(addr *net.UDPAddr) ClientKey {
	k := ClientKey{Port: addr.Port, Zone: addr.Zone}
	copy(k.IP[:], addr.IP.To16())
	return k
}

func (s *p5Server) sendTo(addr *net.UDPAddr, pkt []byte) {
	if len(pkt) > 3 {
		if ref, ok := s.byAddr[p5ClientKey(addr)]; ok {
			if g := s.groups[ref.groupKey]; g != nil {
				networkMetrics.SentBytes(len(pkt), P5Kind(pkt[3]).String(), g.metrics, nil)
			}
		}
	}
	if err := s.send(addr, pkt); err != nil {
		log.Printf("p5: (%v) send: %v\n", addr, err)
	}
}

// handle processes a p5 packet body (the bytes after the protocol byte).
func (s *p5Server) handle(addr *net.UDPAddr, body []byte) {
	if len(body) < 1 {
		return
	}
	kind := P5Kind(body[0])
	body = body[1:]
	key := p5ClientKey(addr)

	switch kind {
	case P5JoinGroup:
		j, err := p5DecodeJoin(body)
		if err != nil {
			log.Printf("p5: (%v) join: %v\n", addr, err)
			return
		}
		s.join(addr, key, &j)
		if ref, ok := s.byAddr[key]; ok {
			networkMetrics.ReceivedBytes(len(body)+4, kind.String(), s.groups[ref.groupKey].metrics, nil)
		}
		return
	case P5LeaveGroup:
		if ref, ok := s.byAddr[key]; ok {
			networkMetrics.ReceivedBytes(len(body)+4, kind.String(), s.groups[ref.groupKey].metrics, nil)
			s.leave(key, P5LeftLeft)
		}
		return
	}

	if kind >= 0x80 || kind > P5BroadcastSector || kind == 0 {
		// server → client kinds and unknown kinds are dropped without a nak:
		return
	}

	ref, ok := s.byAddr[key]
	if !ok {
		s.sendTo(addr, append(p5Packet(P5JoinNak, 1), P5NakNotJoined))
		return
	}
	g := s.groups[ref.groupKey]
	sl := &g.Slots[ref.index]
	sl.LastSeen = s.now()
	networkMetrics.ReceivedBytes(len(body)+4, kind.String(), g.metrics, nil)

	r := &p5Reader{b: body}
	switch kind {
	case P5JoinSector, P5LeaveSector:
		seq := r.u8()
		var sector uint32
		if kind == P5JoinSector {
			sector = r.u32()
		}
		if r.err != nil {
			return
		}
		if !sl.SectorSeqSet || int8(seq-sl.SectorSeq) > 0 {
			sl.SectorSeq, sl.SectorSeqSet = seq, true
			sl.InSector, sl.Sector = kind == P5JoinSector, sector
		}
		s.sendTo(&sl.Addr, append(p5Packet(P5SectorAck, 1), seq))
	case P5Echo:
		t := r.u64()
		if r.err != nil {
			return
		}
		pkt := p5Packet(P5EchoReply, 16)
		pkt = binary.LittleEndian.AppendUint64(pkt, t)
		pkt = binary.LittleEndian.AppendUint64(pkt, uint64(s.now().UnixNano()))
		s.sendTo(&sl.Addr, pkt)
	case P5WhoIs:
		var indexes []uint16
		for len(r.b) >= 2 {
			indexes = append(indexes, r.u16())
		}
		s.sendRoster(g, &sl.Addr, indexes)
	case P5FactPut:
		factNum := r.u8()
		size := int(r.u32())
		chunk := int(r.u8())
		data := r.rest()
		if r.err != nil {
			return
		}
		s.factPut(g, ref.index, factNum, size, chunk, data)
	case P5FactGet:
		for len(r.b) >= 11 {
			index := r.u16()
			factNum := r.u8()
			chunks := r.u64()
			s.factGet(g, &sl.Addr, index, factNum, chunks)
		}
	case P5BroadcastAll, P5BroadcastSector:
		var target uint32
		if kind == P5BroadcastSector {
			target = r.u32()
		}
		data := r.rest()
		if r.err != nil {
			return
		}
		s.relay(g, ref.index, kind == P5BroadcastSector, target, data)
	}
}

func (s *p5Server) relay(g *p5Group, from uint16, sector bool, target uint32, data []byte) {
	kind, hdr := P5RelayAll, 4
	if sector {
		kind, hdr = P5RelaySector, 8
	}
	pkt := p5Packet(kind, hdr+len(data))
	pkt = binary.LittleEndian.AppendUint16(pkt, from)
	pkt = binary.LittleEndian.AppendUint16(pkt, uint16(s.now().UnixMilli()))
	if sector {
		pkt = binary.LittleEndian.AppendUint32(pkt, target)
	}
	pkt = append(pkt, data...)

	for i := range g.Slots {
		c := &g.Slots[i]
		if c.State != p5SlotLive || i == int(from) {
			continue
		}
		if sector && !(c.InSector && c.Sector == target) {
			continue
		}
		s.sendTo(&c.Addr, pkt)
	}
}

// broadcast sends pkt to every live slot of g except the one at except (-1 for none).
func (s *p5Server) broadcast(g *p5Group, except int, pkt []byte) {
	for i := range g.Slots {
		c := &g.Slots[i]
		if c.State != p5SlotLive || i == except {
			continue
		}
		s.sendTo(&c.Addr, pkt)
	}
}

func (s *p5Server) join(addr *net.UDPAddr, key ClientKey, j *P5Join) {
	now := s.now()
	groupKey := calcGroupKey(j.Group)

	if ref, ok := s.byAddr[key]; ok {
		g := s.groups[ref.groupKey]
		sl := &g.Slots[ref.index]
		if int8(j.JoinSeq-sl.JoinSeq) < 0 {
			// a delayed join must not undo a newer one:
			return
		}
		sl.LastSeen = now
		switch {
		case sl.SessionID != j.SessionID:
			// the client restarted:
			s.leave(key, P5LeftLeft)
		case ref.groupKey == groupKey:
			// idempotent; update the name and info:
			sl.JoinSeq = j.JoinSeq
			if sl.Name != j.Name || string(sl.Info) != string(j.Info) {
				sl.Name, sl.Info = j.Name, j.Info
				s.broadcastPlayerInfo(g, int(ref.index))
			}
			s.sendJoinAck(sl, ref.index, now)
			return
		default:
			s.leave(key, P5LeftMoved)
		}
	}

	g, ok := s.groups[groupKey]
	if !ok {
		g = &p5Group{
			Key:      groupKey,
			metrics:  &ClientGroup{Group: groupKey, AnonymizedName: generateAnonymizedName()},
			Sessions: make(map[uint64]*p5Session),
		}
		s.groups[groupKey] = g
		log.Printf("p5: [group %s] new group\n", groupKey)
		reportTotalGroups()
	}

	idx, migrated, retaken := -1, false, false
	// the same session live under another address (NAT rebinding, changed local port) keeps its slot:
	for i := range g.Slots {
		c := &g.Slots[i]
		if c.State == p5SlotLive && c.SessionID == j.SessionID {
			delete(s.byAddr, c.Key)
			idx, migrated = i, true
			break
		}
	}
	// the same session takes its slot back during the grace period:
	if idx < 0 {
		for i := range g.Slots {
			c := &g.Slots[i]
			if c.State == p5SlotGrace && c.SessionID == j.SessionID && now.Before(c.GraceUntil) {
				idx, retaken = i, true
				break
			}
		}
	}
	if idx < 0 {
		for i := range g.Slots {
			c := &g.Slots[i]
			if c.State == p5SlotFree || (c.State == p5SlotGrace && !now.Before(c.GraceUntil)) {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		if len(g.Slots) >= s.maxSlots {
			s.sendTo(addr, append(p5Packet(P5JoinNak, 1), P5NakGroupFull))
			if len(g.Slots) == 0 {
				delete(s.groups, groupKey)
			}
			return
		}
		g.Slots = append(g.Slots, p5Slot{})
		idx = len(g.Slots) - 1
	}

	sl := &g.Slots[idx]
	old := *sl
	*sl = p5Slot{
		State:     p5SlotLive,
		Addr:      *addr,
		Key:       key,
		SessionID: j.SessionID,
		JoinSeq:   j.JoinSeq,
		Name:      j.Name,
		Info:      j.Info,
		LastSeen:  now,
	}
	if migrated {
		// keep the sector the player is in:
		sl.InSector, sl.Sector, sl.SectorSeq, sl.SectorSeqSet = old.InSector, old.Sector, old.SectorSeq, old.SectorSeqSet
	}
	s.byAddr[key] = p5Ref{groupKey: groupKey, index: uint16(idx)}
	if _, ok := g.Sessions[j.SessionID]; !ok {
		g.Sessions[j.SessionID] = &p5Session{}
	}

	log.Printf("p5: [group %s] (%v) join index %d (migrated=%v retaken=%v)\n", groupKey, addr, idx, migrated, retaken)

	s.sendJoinAck(sl, uint16(idx), now)
	if !migrated {
		// tell the others about the new player:
		s.broadcastPlayerInfo(g, idx)
		if pkts := s.factListPackets(g, idx); len(pkts) > 0 {
			for _, pkt := range pkts {
				s.broadcast(g, idx, pkt)
			}
		}
	}
	// and the new player about everyone, itself included (its own fact-list gives it its facts' hashes):
	s.sendRoster(g, addr, nil)
}

func (s *p5Server) sendJoinAck(sl *p5Slot, index uint16, now time.Time) {
	pkt := p5Packet(P5JoinAck, 11)
	pkt = append(pkt, sl.JoinSeq)
	pkt = binary.LittleEndian.AppendUint16(pkt, index)
	pkt = binary.LittleEndian.AppendUint64(pkt, uint64(now.UnixNano()))
	s.sendTo(&sl.Addr, pkt)
}

func (s *p5Server) broadcastPlayerInfo(g *p5Group, index int) {
	c := &g.Slots[index]
	pkt := p5Packet(P5PlayerInfo, p5PlayerInfoEntrySize(c.Name, c.Info))
	pkt = p5AppendPlayerInfoEntry(pkt, uint16(index), c.Name, c.Info)
	s.broadcast(g, index, pkt)
}

// sendRoster sends player-info and fact-list for the requested indexes (nil = every live player) to addr. Indexes
// that aren't live players are left out.
func (s *p5Server) sendRoster(g *p5Group, addr *net.UDPAddr, indexes []uint16) {
	if indexes == nil {
		for i := range g.Slots {
			if g.Slots[i].State == p5SlotLive {
				indexes = append(indexes, uint16(i))
			}
		}
	}

	var pkt []byte
	var lists [][]byte
	for _, idx := range indexes {
		if int(idx) >= len(g.Slots) || g.Slots[idx].State != p5SlotLive {
			continue
		}
		c := &g.Slots[idx]
		n := p5PlayerInfoEntrySize(c.Name, c.Info)
		if pkt != nil && len(pkt)+n > p5PackLimit {
			s.sendTo(addr, pkt)
			pkt = nil
		}
		if pkt == nil {
			pkt = p5Packet(P5PlayerInfo, p5PackLimit)
		}
		pkt = p5AppendPlayerInfoEntry(pkt, idx, c.Name, c.Info)
		lists = append(lists, s.factListPackets(g, int(idx))...)
	}
	if pkt != nil {
		s.sendTo(addr, pkt)
	}
	for _, l := range lists {
		s.sendTo(addr, l)
	}
}

// factListPackets returns the fact-list packets for the complete facts of the player at index.
func (s *p5Server) factListPackets(g *p5Group, index int) (pkts [][]byte) {
	sess := g.Sessions[g.Slots[index].SessionID]
	if sess == nil {
		return nil
	}
	var pkt []byte
	for n, f := range sess.Facts {
		if f == nil || !f.Complete {
			continue
		}
		if pkt != nil && len(pkt)+p5FactListEntrySize > p5PackLimit {
			pkts = append(pkts, pkt)
			pkt = nil
		}
		if pkt == nil {
			pkt = p5Packet(P5FactList, p5PackLimit)
			pkt = binary.LittleEndian.AppendUint16(pkt, uint16(index))
		}
		pkt = p5AppendFactListEntry(pkt, uint8(n), f)
	}
	if pkt != nil {
		pkts = append(pkts, pkt)
	}
	return
}

func p5AppendFactListEntry(pkt []byte, factNum uint8, f *p5Fact) []byte {
	pkt = append(pkt, factNum)
	pkt = binary.LittleEndian.AppendUint32(pkt, uint32(f.Size))
	return append(pkt, f.Hash[:]...)
}

// leave removes the client at key from its group, reserves its slot for the grace period and tells the others.
func (s *p5Server) leave(key ClientKey, reason uint8) {
	ref, ok := s.byAddr[key]
	if !ok {
		return
	}
	delete(s.byAddr, key)
	g := s.groups[ref.groupKey]
	sl := &g.Slots[ref.index]
	log.Printf("p5: [group %s] (%v) leave index %d reason %d\n", g.Key, &sl.Addr, ref.index, reason)
	*sl = p5Slot{
		State:      p5SlotGrace,
		SessionID:  sl.SessionID,
		GraceUntil: s.now().Add(s.slotGrace),
	}
	pkt := p5Packet(P5PlayerLeft, 3)
	pkt = binary.LittleEndian.AppendUint16(pkt, ref.index)
	pkt = append(pkt, reason)
	s.broadcast(g, -1, pkt)
}

// expire times out silent clients, ends grace periods and removes groups with no live or reserved slots.
func (s *p5Server) expire() {
	now := s.now()
	for key, ref := range s.byAddr {
		sl := &s.groups[ref.groupKey].Slots[ref.index]
		if sl.LastSeen.Add(s.disconnectTimeout).Before(now) {
			s.leave(key, P5LeftTimedOut)
		}
	}
	for groupKey, g := range s.groups {
		used := 0
		for i := range g.Slots {
			c := &g.Slots[i]
			if c.State == p5SlotGrace && !now.Before(c.GraceUntil) {
				*c = p5Slot{}
			}
			if c.State != p5SlotFree {
				used++
			}
		}
		if used == 0 {
			s.dropGroup(groupKey)
		}
	}
}

// dropGroup removes a group and releases its facts.
func (s *p5Server) dropGroup(groupKey string) {
	g := s.groups[groupKey]
	for _, sess := range g.Sessions {
		for _, f := range sess.Facts {
			if f != nil && f.Complete {
				s.releaseBlob(f.Hash)
			}
		}
	}
	delete(s.groups, groupKey)
	log.Printf("p5: [group %s] forget group\n", groupKey)
}

func (s *p5Server) releaseBlob(h [p5HashSize]byte) {
	b := s.blobs[h]
	if b == nil {
		return
	}
	b.refs--
	if b.refs <= 0 {
		delete(s.blobs, h)
	}
}

func (s *p5Server) sendFactStatus(addr *net.UDPAddr, factNum uint8, state uint8, received uint64) {
	pkt := p5Packet(P5FactStatus, 10)
	pkt = append(pkt, factNum, state)
	pkt = binary.LittleEndian.AppendUint64(pkt, received)
	s.sendTo(addr, pkt)
}

func (s *p5Server) factPut(g *p5Group, index uint16, factNum uint8, size int, chunk int, data []byte) {
	sl := &g.Slots[index]
	sess := g.Sessions[sl.SessionID]
	f := sess.Facts[factNum]

	if f != nil && f.Complete {
		if f.Size == size {
			s.sendFactStatus(&sl.Addr, factNum, P5FactComplete, f.Received)
		} else {
			s.sendFactStatus(&sl.Addr, factNum, P5FactRejected, 0)
		}
		return
	}
	if size < 1 || size > p5FactMaxSize || chunk >= p5ChunkCount(size) || len(data) != p5ChunkLen(size, chunk) {
		s.sendFactStatus(&sl.Addr, factNum, P5FactRejected, 0)
		return
	}
	if f == nil {
		if sess.Bytes+size > s.sessionQuota || g.FactBytes+size > s.groupQuota {
			s.sendFactStatus(&sl.Addr, factNum, P5FactRejected, 0)
			return
		}
		f = &p5Fact{Size: size, buf: make([]byte, size)}
		sess.Facts[factNum] = f
		sess.Bytes += size
		g.FactBytes += size
	}
	if f.Size != size {
		s.sendFactStatus(&sl.Addr, factNum, P5FactRejected, f.Received)
		return
	}

	copy(f.buf[chunk*p5FactChunkSize:], data)
	f.Received |= uint64(1) << chunk
	if f.Received != p5AllChunks(size) {
		s.sendFactStatus(&sl.Addr, factNum, P5FactReceiving, f.Received)
		return
	}

	// complete: hash, share the bytes with identical facts, and tell everyone (the uploader too, which learns its
	// fact's hash from its own fact-list):
	sum := sha256.Sum256(f.buf)
	copy(f.Hash[:], sum[:p5HashSize])
	b := s.blobs[f.Hash]
	if b == nil {
		b = &p5Blob{data: f.buf}
		s.blobs[f.Hash] = b
	}
	b.refs++
	f.Data, f.buf, f.Complete = b.data, nil, true
	log.Printf("p5: [group %s] index %d fact %d complete, %d bytes\n", g.Key, index, factNum, size)

	s.sendFactStatus(&sl.Addr, factNum, P5FactComplete, f.Received)
	pkt := p5Packet(P5FactList, 2+p5FactListEntrySize)
	pkt = binary.LittleEndian.AppendUint16(pkt, index)
	pkt = p5AppendFactListEntry(pkt, factNum, f)
	s.broadcast(g, -1, pkt)
}

func (s *p5Server) factGet(g *p5Group, addr *net.UDPAddr, index uint16, factNum uint8, chunks uint64) {
	if int(index) >= len(g.Slots) || g.Slots[index].State != p5SlotLive {
		return
	}
	sess := g.Sessions[g.Slots[index].SessionID]
	if sess == nil {
		return
	}
	f := sess.Facts[factNum]
	if f == nil || !f.Complete {
		return
	}
	chunks &= p5AllChunks(f.Size)
	for i := 0; chunks != 0; i++ {
		if chunks&1 != 0 {
			o := i * p5FactChunkSize
			n := p5ChunkLen(f.Size, i)
			pkt := p5Packet(P5FactData, 4+n)
			pkt = binary.LittleEndian.AppendUint16(pkt, index)
			pkt = append(pkt, factNum, uint8(i))
			pkt = append(pkt, f.Data[o:o+n]...)
			s.sendTo(addr, pkt)
		}
		chunks >>= 1
	}
}

// liveCount returns the number of live clients in every group.
func (s *p5Server) liveCount() (n int) {
	for _, g := range s.groups {
		n += g.liveCount()
	}
	return
}

func (g *p5Group) liveCount() (n int) {
	for i := range g.Slots {
		if g.Slots[i].State == p5SlotLive {
			n++
		}
	}
	return
}

// reportGroups reports each group's live client count.
func (s *p5Server) reportGroups() {
	for _, g := range s.groups {
		groupMetrics.GroupClients(g.metrics, g.liveCount())
	}
}
