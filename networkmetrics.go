package main

import (
	"sync"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go"
	influxApi "github.com/influxdata/influxdb-client-go/api"
)

// NetworkMetrics counts bytes on the wire. client is nil for protocols that don't report per client (p5).
type NetworkMetrics interface {
	ReceivedBytes(n int, kind string, group *ClientGroup, client *Client)
	SentBytes(n int, kind string, group *ClientGroup, client *Client)
}

type nullNetworkMetrics struct{}

func (m nullNetworkMetrics) ReceivedBytes(n int, kind string, group *ClientGroup, client *Client) {}
func (m nullNetworkMetrics) SentBytes(n int, kind string, group *ClientGroup, client *Client)     {}

type netSeries struct {
	group, groupAnon, client, kind string
}

type netCounts struct {
	received, sent         int64
	receivedPkts, sentPkts int64
}

// influxNetworkMetrics sums bytes and packets per series (group, client, kind) in memory and writes one point per
// series on every whole second, instead of one point per packet.
type influxNetworkMetrics struct {
	w influxApi.WriteAPI

	mu     sync.Mutex
	counts map[netSeries]*netCounts
	done   chan struct{}
}

func newInfluxNetworkMetrics(w influxApi.WriteAPI) *influxNetworkMetrics {
	m := &influxNetworkMetrics{
		w:      w,
		counts: make(map[netSeries]*netCounts),
		done:   make(chan struct{}),
	}
	go m.run()
	return m
}

func (m *influxNetworkMetrics) add(n int, kind string, group *ClientGroup, client *Client, sent bool) {
	s := netSeries{group: group.Group, groupAnon: group.AnonymizedName, kind: kind}
	if client != nil {
		s.client = client.String()
	}

	m.mu.Lock()
	c := m.counts[s]
	if c == nil {
		c = &netCounts{}
		m.counts[s] = c
	}
	if sent {
		c.sent += int64(n)
		c.sentPkts++
	} else {
		c.received += int64(n)
		c.receivedPkts++
	}
	m.mu.Unlock()
}

func (m *influxNetworkMetrics) ReceivedBytes(n int, kind string, group *ClientGroup, client *Client) {
	m.add(n, kind, group, client, false)
}

func (m *influxNetworkMetrics) SentBytes(n int, kind string, group *ClientGroup, client *Client) {
	m.add(n, kind, group, client, true)
}

// run flushes on each whole second until Close.
func (m *influxNetworkMetrics) run() {
	for {
		now := time.Now()
		next := now.Truncate(time.Second).Add(time.Second)
		select {
		case <-time.After(next.Sub(now)):
			m.flush(next.Add(-time.Second))
		case <-m.done:
			return
		}
	}
}

// flush writes the counts accumulated since the last flush as points stamped t and starts over.
func (m *influxNetworkMetrics) flush(t time.Time) {
	m.mu.Lock()
	counts := m.counts
	m.counts = make(map[netSeries]*netCounts, len(counts))
	m.mu.Unlock()

	for s, c := range counts {
		p := influxdb2.NewPointWithMeasurement("net").
			SetTime(t).
			AddTag("group", s.group).
			AddTag("group_anon", s.groupAnon).
			AddTag("kind", s.kind)
		if s.client != "" {
			p.AddTag("client", s.client)
		}
		if c.receivedPkts > 0 {
			p.AddField("received", c.received).AddField("received_packets", c.receivedPkts)
		}
		if c.sentPkts > 0 {
			p.AddField("sent", c.sent).AddField("sent_packets", c.sentPkts)
		}
		m.w.WritePoint(p)
	}
}

// Close stops the flush loop and writes what is left.
func (m *influxNetworkMetrics) Close() {
	close(m.done)
	m.flush(time.Now().Truncate(time.Second))
}
