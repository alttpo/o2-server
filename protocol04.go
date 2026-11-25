package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"time"
)

// Protocol 0x04 mirrors protocol 0x03's GroupMessage contract (see p3.proto) using a simple
// hand-rolled binary encoding instead of protobuf. All multi-byte integers are little-endian.
//
// Packet layout (after the common 2-byte header 0x651F and 1-byte protocol 0x04):
//
//	GroupMessage:
//	  uint8   groupLength
//	  [N]byte group            (N = groupLength, max 255)
//	  int64   playerTime
//	  int64   serverTime
//	  uint32  playerIndex
//	  uint64  playerInSector
//	  uint8   kind             (discriminates the `oneof message`; see P04Kind)
//	  ...     kind-specific body:
//
//	  P04JoinGroup       (0x01): (empty)
//	  P04BroadcastAll    (0x02): uint16 dataLength, [N]byte data
//	  P04BroadcastSector (0x03): uint64 targetSector, uint16 dataLength, [N]byte data
//	  P04Echo            (0x04): uint16 dataLength, [N]byte data
//
// Trailing bytes after the kind-specific body are ignored.

type P04Kind uint8

const (
	P04JoinGroup       = P04Kind(0x01)
	P04BroadcastAll    = P04Kind(0x02)
	P04BroadcastSector = P04Kind(0x03)
	P04Echo            = P04Kind(0x04)
)

func (k P04Kind) String() string {
	switch k {
	case P04JoinGroup:
		return "p4:joinGroup"
	case P04BroadcastAll:
		return "p4:broadcastAll"
	case P04BroadcastSector:
		return "p4:broadcastSector"
	case P04Echo:
		return "p4:echo"
	}
	return fmt.Sprintf("p4:unknown(0x%02x)", uint8(k))
}

type P04GroupMessage struct {
	Group          string
	PlayerTime     int64
	ServerTime     int64
	PlayerIndex    uint32
	PlayerInSector uint64

	Kind P04Kind

	// TargetSector is only used for P04BroadcastSector:
	TargetSector uint64
	// Data is used for P04BroadcastAll, P04BroadcastSector, and P04Echo:
	Data []byte
}

var (
	errP04Truncated    = errors.New("p4: message truncated")
	errP04UnknownKind  = errors.New("p4: unknown message kind")
	errP04GroupTooLong = errors.New("p4: group name exceeds 255 bytes")
	errP04DataTooLong  = errors.New("p4: data exceeds 65535 bytes")
)

// p04Reader is a minimal bounds-checked little-endian reader over a byte slice.
type p04Reader struct {
	b   []byte
	err error
}

func (r *p04Reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if len(r.b) < n {
		r.err = errP04Truncated
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *p04Reader) u8() uint8 {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *p04Reader) u16() uint16 {
	if v := r.take(2); v != nil {
		return binary.LittleEndian.Uint16(v)
	}
	return 0
}

func (r *p04Reader) u32() uint32 {
	if v := r.take(4); v != nil {
		return binary.LittleEndian.Uint32(v)
	}
	return 0
}

func (r *p04Reader) u64() uint64 {
	if v := r.take(8); v != nil {
		return binary.LittleEndian.Uint64(v)
	}
	return 0
}

func (r *p04Reader) tinyString() string {
	n := int(r.u8())
	return string(r.take(n))
}

func (r *p04Reader) bytes16() []byte {
	n := int(r.u16())
	v := r.take(n)
	if v == nil {
		return nil
	}
	// copy so the message does not alias the receive buffer:
	c := make([]byte, len(v))
	copy(c, v)
	return c
}

// UnmarshalP04 decodes a GroupMessage body (the bytes following the protocol byte).
func UnmarshalP04(b []byte, gm *P04GroupMessage) error {
	r := &p04Reader{b: b}

	gm.Group = r.tinyString()
	gm.PlayerTime = int64(r.u64())
	gm.ServerTime = int64(r.u64())
	gm.PlayerIndex = r.u32()
	gm.PlayerInSector = r.u64()
	gm.Kind = P04Kind(r.u8())
	gm.TargetSector = 0
	gm.Data = nil
	if r.err != nil {
		return r.err
	}

	switch gm.Kind {
	case P04JoinGroup:
	case P04BroadcastAll, P04Echo:
		gm.Data = r.bytes16()
	case P04BroadcastSector:
		gm.TargetSector = r.u64()
		gm.Data = r.bytes16()
	default:
		return errP04UnknownKind
	}

	return r.err
}

// AppendP04 encodes gm and appends it to dst, returning the extended slice.
func AppendP04(dst []byte, gm *P04GroupMessage) ([]byte, error) {
	if len(gm.Group) > 0xFF {
		return dst, errP04GroupTooLong
	}
	if len(gm.Data) > 0xFFFF {
		return dst, errP04DataTooLong
	}

	var tmp [8]byte

	dst = append(dst, uint8(len(gm.Group)))
	dst = append(dst, gm.Group...)

	binary.LittleEndian.PutUint64(tmp[:8], uint64(gm.PlayerTime))
	dst = append(dst, tmp[:8]...)
	binary.LittleEndian.PutUint64(tmp[:8], uint64(gm.ServerTime))
	dst = append(dst, tmp[:8]...)
	binary.LittleEndian.PutUint32(tmp[:4], gm.PlayerIndex)
	dst = append(dst, tmp[:4]...)
	binary.LittleEndian.PutUint64(tmp[:8], gm.PlayerInSector)
	dst = append(dst, tmp[:8]...)

	dst = append(dst, uint8(gm.Kind))

	appendData := func() {
		binary.LittleEndian.PutUint16(tmp[:2], uint16(len(gm.Data)))
		dst = append(dst, tmp[:2]...)
		dst = append(dst, gm.Data...)
	}

	switch gm.Kind {
	case P04JoinGroup:
	case P04BroadcastAll, P04Echo:
		appendData()
	case P04BroadcastSector:
		binary.LittleEndian.PutUint64(tmp[:8], gm.TargetSector)
		dst = append(dst, tmp[:8]...)
		appendData()
	default:
		return dst, errP04UnknownKind
	}

	return dst, nil
}

// make04Packet builds a complete UDP packet: header, protocol byte, and encoded GroupMessage.
func make04Packet(gm *P04GroupMessage) ([]byte, error) {
	pkt := make([]byte, 3, 3+1+len(gm.Group)+8+8+4+8+1+8+2+len(gm.Data))
	binary.LittleEndian.PutUint16(pkt[0:2], 25887)
	pkt[2] = 0x04
	return AppendP04(pkt, gm)
}

func processProtocol04(message UDPMessage, body []byte) (fatalErr error) {
	// parse message; malformed client input is logged and dropped, never fatal:
	gm := &P04GroupMessage{}
	if err := UnmarshalP04(body, gm); err != nil {
		log.Printf("(%v) %v\n", message.ReceivedFrom, err)
		return
	}

	// trim whitespace and convert to lowercase for key lookup:
	group := gm.Group
	groupKey := calcGroupKey(group)
	clientGroup := findGroupOrCreate(groupKey)

	// create a key that represents the client from the received address:
	addr := message.ReceivedFrom
	clientKey := ClientKey{
		Port: addr.Port,
		Zone: addr.Zone,
	}
	copy(clientKey.IP[:], addr.IP)

	client, ci := findClientOrCreate(clientGroup, clientKey, addr, group, groupKey)

	// update client's sector:
	client.Sector = gm.PlayerInSector

	// prepare the message for rebroadcast:
	gm.PlayerIndex = uint32(ci)
	gm.ServerTime = time.Now().UnixNano()

	metric := gm.Kind.String()
	networkMetrics.ReceivedBytes(len(message.Envelope), metric, clientGroup, client)

	pkt, err := make04Packet(gm)
	if err != nil {
		log.Printf("(%v) %v\n", message.ReceivedFrom, err)
		return
	}

	sendTo := func(c *Client) error {
		if _, err := writeToUDP(pkt, &c.UDPAddr); err != nil {
			return err
		}
		networkMetrics.SentBytes(len(pkt), metric, clientGroup, client)
		return nil
	}

	switch gm.Kind {
	case P04JoinGroup, P04Echo:
		// respond only to the sender:
		return sendTo(client)
	case P04BroadcastAll, P04BroadcastSector:
		for i := range clientGroup.Clients {
			c := &clientGroup.Clients[i]
			if !c.IsAlive || c == client {
				continue
			}
			// for sector broadcasts, player must be in the sector being broadcast to:
			if gm.Kind == P04BroadcastSector && c.Sector != gm.TargetSector {
				continue
			}
			if fatalErr = sendTo(c); fatalErr != nil {
				return
			}
		}
	}

	return
}
