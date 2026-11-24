package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Protocol 0x05 (see PROTOCOL05.md). All integers are little-endian. Every packet starts with the 2-byte magic 0x651F,
// the protocol byte 0x05 and a kind byte; the data of broadcasts, relays and fact chunks runs to the end of the
// datagram.

const p5Protocol = 0x05

type P5Kind uint8

// client → server:
const (
	P5JoinGroup       = P5Kind(0x01)
	P5LeaveGroup      = P5Kind(0x02)
	P5JoinSector      = P5Kind(0x03)
	P5LeaveSector     = P5Kind(0x04)
	P5Echo            = P5Kind(0x05)
	P5WhoIs           = P5Kind(0x06)
	P5FactPut         = P5Kind(0x07)
	P5FactGet         = P5Kind(0x08)
	P5BroadcastAll    = P5Kind(0x09)
	P5BroadcastSector = P5Kind(0x0A)
)

// server → client:
const (
	P5JoinAck     = P5Kind(0x81)
	P5JoinNak     = P5Kind(0x82)
	P5SectorAck   = P5Kind(0x83)
	P5EchoReply   = P5Kind(0x84)
	P5PlayerInfo  = P5Kind(0x85)
	P5PlayerLeft  = P5Kind(0x86)
	P5FactStatus  = P5Kind(0x87)
	P5FactList    = P5Kind(0x88)
	P5FactData    = P5Kind(0x89)
	P5RelayAll    = P5Kind(0x8A)
	P5RelaySector = P5Kind(0x8B)
)

var p5KindNames = map[P5Kind]string{
	P5JoinGroup: "joinGroup", P5LeaveGroup: "leaveGroup", P5JoinSector: "joinSector", P5LeaveSector: "leaveSector",
	P5Echo: "echo", P5WhoIs: "whoIs", P5FactPut: "factPut", P5FactGet: "factGet", P5BroadcastAll: "broadcastAll",
	P5BroadcastSector: "broadcastSector",
	P5JoinAck:         "joinAck", P5JoinNak: "joinNak", P5SectorAck: "sectorAck", P5EchoReply: "echoReply",
	P5PlayerInfo: "playerInfo", P5PlayerLeft: "playerLeft", P5FactStatus: "factStatus", P5FactList: "factList",
	P5FactData: "factData", P5RelayAll: "relayAll", P5RelaySector: "relaySector",
}

func (k P5Kind) String() string {
	if s, ok := p5KindNames[k]; ok {
		return "p5:" + s
	}
	return fmt.Sprintf("p5:unknown(0x%02x)", uint8(k))
}

// join-nak reasons:
const (
	P5NakNotJoined = 0
	P5NakGroupFull = 1
)

// player-left reasons:
const (
	P5LeftLeft     = 0
	P5LeftTimedOut = 1
	P5LeftMoved    = 2
)

// fact-status states:
const (
	P5FactReceiving = 0
	P5FactComplete  = 1
	P5FactRejected  = 2
)

const (
	// p5FactChunkSize is the size of every chunk of a fact but the last:
	p5FactChunkSize = 1024
	// p5FactMaxSize is the largest fact; its 64 chunks fit a u64 bitmap:
	p5FactMaxSize = 64 * p5FactChunkSize
	// p5PackLimit is the most bytes the server packs into one player-info, fact-list or who-is reply packet:
	p5PackLimit = 1200
	// p5HashSize is the size of a fact's hash (SHA-256, truncated):
	p5HashSize = 16
	// p5FactListEntrySize is the size of a fact-list entry: u8 factNum, u32 size, hash:
	p5FactListEntrySize = 1 + 4 + p5HashSize
)

var (
	errP5Truncated = errors.New("p5: message truncated")
	errP5TooLong   = errors.New("p5: field too long")
)

// p5Reader is a bounds-checked little-endian reader.
type p5Reader struct {
	b   []byte
	err error
}

func (r *p5Reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.err = errP5Truncated
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *p5Reader) u8() uint8 {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *p5Reader) u16() uint16 {
	if v := r.take(2); v != nil {
		return binary.LittleEndian.Uint16(v)
	}
	return 0
}

func (r *p5Reader) u32() uint32 {
	if v := r.take(4); v != nil {
		return binary.LittleEndian.Uint32(v)
	}
	return 0
}

func (r *p5Reader) u64() uint64 {
	if v := r.take(8); v != nil {
		return binary.LittleEndian.Uint64(v)
	}
	return 0
}

// tiny reads a u8 length and that many bytes; the result aliases the packet.
func (r *p5Reader) tiny() []byte {
	return r.take(int(r.u8()))
}

// rest returns the remaining bytes.
func (r *p5Reader) rest() []byte {
	if r.err != nil {
		return nil
	}
	v := r.b
	r.b = nil
	return v
}

// p5Packet starts a server → client packet of the given kind.
func p5Packet(kind P5Kind, capacity int) []byte {
	b := make([]byte, 0, 4+capacity)
	b = binary.LittleEndian.AppendUint16(b, 25887)
	return append(b, p5Protocol, uint8(kind))
}

// P5Join is a decoded join-group.
type P5Join struct {
	JoinSeq   uint8
	SessionID uint64
	Group     string
	Name      string
	Info      []byte
	// Auth is the optional auth field, see p5auth.go; empty for a group without a password:
	Auth []byte
}

func p5DecodeJoin(body []byte) (j P5Join, err error) {
	r := &p5Reader{b: body}
	j.JoinSeq = r.u8()
	j.SessionID = r.u64()
	j.Group = string(r.tiny())
	j.Name = string(r.tiny())
	info := r.tiny()
	if r.err != nil {
		return j, r.err
	}
	j.Info = append([]byte(nil), info...)
	if len(r.b) > 0 {
		// older clients stop after the info:
		j.Auth = append([]byte(nil), r.tiny()...)
		if r.err != nil {
			return j, r.err
		}
	}
	return
}

// AppendP5Join encodes a join-group packet (used by tests and clients).
func AppendP5Join(b []byte, j *P5Join) ([]byte, error) {
	if len(j.Group) > 0xFF || len(j.Name) > 0xFF || len(j.Info) > 0xFF || len(j.Auth) > 0xFF {
		return b, errP5TooLong
	}
	b = append(b, j.JoinSeq)
	b = binary.LittleEndian.AppendUint64(b, j.SessionID)
	b = append(b, uint8(len(j.Group)))
	b = append(b, j.Group...)
	b = append(b, uint8(len(j.Name)))
	b = append(b, j.Name...)
	b = append(b, uint8(len(j.Info)))
	b = append(b, j.Info...)
	if len(j.Auth) > 0 {
		b = append(b, uint8(len(j.Auth)))
		b = append(b, j.Auth...)
	}
	return b, nil
}

// p5AppendPlayerInfoEntry appends one player-info entry.
func p5AppendPlayerInfoEntry(b []byte, index uint16, name string, info []byte) []byte {
	b = binary.LittleEndian.AppendUint16(b, index)
	b = append(b, uint8(len(name)))
	b = append(b, name...)
	b = append(b, uint8(len(info)))
	return append(b, info...)
}

func p5PlayerInfoEntrySize(name string, info []byte) int {
	return 2 + 1 + len(name) + 1 + len(info)
}

// p5ChunkCount returns the number of chunks of a fact of size bytes.
func p5ChunkCount(size int) int {
	return (size + p5FactChunkSize - 1) / p5FactChunkSize
}

// p5AllChunks returns the bitmap with every chunk of a fact of size bytes set.
func p5AllChunks(size int) uint64 {
	n := p5ChunkCount(size)
	if n >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << n) - 1
}

// p5ChunkLen returns the length of chunk i of a fact of size bytes.
func p5ChunkLen(size int, i int) int {
	n := size - i*p5FactChunkSize
	if n > p5FactChunkSize {
		n = p5FactChunkSize
	}
	return n
}
