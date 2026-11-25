package main

import (
	"log"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"time"
)

// Network impairment for local testing, applied to every packet the server
// receives (before the event loop sees it) and every packet it sends:
//
//	O2_LAG_MS       delay each packet this many milliseconds each way, so a
//	                round trip through the server gains twice the value
//	O2_LOSS_PCT     percent chance (0-100, fractions allowed) a packet is dropped
//	O2_REORDER_PCT  percent chance (0-100) a packet is held back an extra
//	                O2_REORDER_MS (default 20) so the packets behind it overtake it
//
// Unset or 0 means off. With all of them off packets go straight through.
var (
	lag          time.Duration
	lossPct      float64
	reorderPct   float64
	reorderExtra = 20 * time.Millisecond
	impaired     bool
)

// lagOut is the outbound delay line; nil when there's no impairment.
var lagOut chan lagged[outPacket]

type lagged[T any] struct {
	due time.Time
	v   T
}

type outPacket struct {
	pkt  []byte
	addr net.UDPAddr
}

func envMs(name string) (time.Duration, bool) {
	s := os.Getenv(name)
	if s == "" {
		return 0, false
	}
	ms, err := strconv.Atoi(s)
	if err != nil || ms < 0 {
		log.Fatalf("%s=%q: want a non-negative whole number of milliseconds", name, s)
	}
	return time.Duration(ms) * time.Millisecond, true
}

func envPct(name string) float64 {
	s := os.Getenv(name)
	if s == "" {
		return 0
	}
	pct, err := strconv.ParseFloat(s, 64)
	if err != nil || pct < 0 || pct > 100 {
		log.Fatalf("%s=%q: want a percentage from 0 to 100", name, s)
	}
	return pct
}

func initLag() {
	lag, _ = envMs("O2_LAG_MS")
	lossPct = envPct("O2_LOSS_PCT")
	reorderPct = envPct("O2_REORDER_PCT")
	if d, ok := envMs("O2_REORDER_MS"); ok {
		reorderExtra = d
	}

	impaired = lag > 0 || lossPct > 0 || reorderPct > 0
	if !impaired {
		return
	}
	log.Printf("simulating network: lag %v each way, loss %g%%, reorder %g%% (held back %v)",
		lag, lossPct, reorderPct, reorderExtra)

	lagOut = make(chan lagged[outPacket], 65536)
	go delayLine(lagOut, sendNow)
}

func sendNow(p outPacket) {
	if _, err := conn.WriteToUDP(p.pkt, &p.addr); err != nil {
		log.Print(err)
	}
}

func chance(pct float64) bool {
	return pct > 0 && rand.Float64()*100 < pct
}

// impair drops v, sends it the long way round to be reordered, or puts it on
// the delay line, by the configured chances.
func impair[T any](v T, line chan<- lagged[T], deliver func(T)) {
	if chance(lossPct) {
		return
	}
	if chance(reorderPct) {
		time.AfterFunc(lag+reorderExtra, func() { deliver(v) })
		return
	}
	line <- lagged[T]{due: time.Now().Add(lag), v: v}
}

// delayLine delivers each item once its due time arrives. The delay is the same
// for every item, so items come out in the order they went in.
func delayLine[T any](in <-chan lagged[T], deliver func(T)) {
	for l := range in {
		if d := time.Until(l.due); d > 0 {
			time.Sleep(d)
		}
		deliver(l.v)
	}
}

// lagIn puts received messages through the inbound impairment when there is
// one, returning the channel the event loop should read from.
func lagIn(messages chan UDPMessage) <-chan UDPMessage {
	if !impaired {
		return messages
	}
	line := make(chan lagged[UDPMessage], 65536)
	out := make(chan UDPMessage)
	deliver := func(m UDPMessage) { out <- m }
	go func() {
		for m := range messages {
			impair(m, line, deliver)
		}
		close(line)
	}()
	go func() {
		delayLine(line, deliver)
		close(out)
	}()
	return out
}

// writeToUDP sends pkt to addr through the outbound impairment when there is
// one. An impaired send copies pkt and addr (callers reuse their buffers),
// reports success even if the packet is dropped, and logs write errors instead
// of returning them.
func writeToUDP(pkt []byte, addr *net.UDPAddr) (int, error) {
	if !impaired {
		return conn.WriteToUDP(pkt, addr)
	}
	impair(outPacket{pkt: append([]byte(nil), pkt...), addr: *addr}, lagOut, sendNow)
	return len(pkt), nil
}
