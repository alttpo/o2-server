package main

import (
	"bytes"
	"reflect"
	"testing"
)

func TestP04RoundTrip(t *testing.T) {
	cases := []P04GroupMessage{
		{Group: "mygroup", PlayerTime: -12345, ServerTime: 987654321, PlayerIndex: 3, PlayerInSector: 0x1122, Kind: P04JoinGroup},
		{Group: "g", PlayerTime: 1, Kind: P04BroadcastAll, Data: []byte{1, 2, 3}},
		{Group: "", Kind: P04BroadcastSector, TargetSector: 0xDEADBEEFCAFE, Data: []byte{}},
		{Group: "echo", Kind: P04Echo, Data: bytes.Repeat([]byte{0xAB}, 300)},
	}
	for _, want := range cases {
		b, err := AppendP04(nil, &want)
		if err != nil {
			t.Fatalf("%v: marshal: %v", want.Kind, err)
		}
		var got P04GroupMessage
		if err := UnmarshalP04(b, &got); err != nil {
			t.Fatalf("%v: unmarshal: %v", want.Kind, err)
		}
		// normalize empty vs nil for comparison:
		if len(want.Data) == 0 {
			want.Data, got.Data = nil, nil
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%v: mismatch:\nwant %+v\n got %+v", want.Kind, want, got)
		}

		// every strict prefix must fail as truncated:
		for n := 0; n < len(b); n++ {
			if err := UnmarshalP04(b[:n], &got); err == nil {
				t.Fatalf("%v: expected error for %d/%d bytes", want.Kind, n, len(b))
			}
		}
	}
}

func TestP04WireFormat(t *testing.T) {
	gm := P04GroupMessage{
		Group:          "ab",
		PlayerTime:     0x0102030405060708,
		ServerTime:     0x1112131415161718,
		PlayerIndex:    0x21222324,
		PlayerInSector: 0x3132333435363738,
		Kind:           P04BroadcastSector,
		TargetSector:   0x4142434445464748,
		Data:           []byte{0xEE, 0xFF},
	}
	got, err := make04Packet(&gm)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x1F, 0x65, 0x04, // header + protocol
		0x02, 'a', 'b',
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
		0x24, 0x23, 0x22, 0x21,
		0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31,
		0x03,
		0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41,
		0x02, 0x00, 0xEE, 0xFF,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire mismatch:\nwant % x\n got % x", want, got)
	}
}

func TestP04UnknownKind(t *testing.T) {
	b, _ := AppendP04(nil, &P04GroupMessage{Kind: P04JoinGroup})
	b[len(b)-1] = 0x7F
	if err := UnmarshalP04(b, &P04GroupMessage{}); err != errP04UnknownKind {
		t.Fatalf("expected errP04UnknownKind, got %v", err)
	}
}
