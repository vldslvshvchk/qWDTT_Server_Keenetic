package qwdtt

import (
	"sync"
	"sync/atomic"
	"time"
)

type TrafficStats struct {
	mu         sync.Mutex
	last       time.Time
	rx         atomic.Uint64
	tx         atomic.Uint64
	prevRX     uint64
	prevTX     uint64
	prev       time.Time
	lastRXRate float64
	lastTXRate float64
	lastActive time.Time
}

type TrafficSnapshot struct {
	RXBytes uint64  `json:"rxBytes"`
	TXBytes uint64  `json:"txBytes"`
	RXRate  float64 `json:"rxRate"`
	TXRate  float64 `json:"txRate"`
}

func (t *TrafficStats) AddRX(n int) {
	if t != nil && n > 0 {
		t.rx.Add(uint64(n))
	}
}
func (t *TrafficStats) AddTX(n int) {
	if t != nil && n > 0 {
		t.tx.Add(uint64(n))
	}
}
func (t *TrafficStats) Snapshot() TrafficSnapshot {
	if t == nil {
		return TrafficSnapshot{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	rx := t.rx.Load()
	tx := t.tx.Load()
	if t.prev.IsZero() {
		t.prev, t.prevRX, t.prevTX = now, rx, tx
		return TrafficSnapshot{RXBytes: rx, TXBytes: tx}
	}
	d := now.Sub(t.prev).Seconds()
	if d <= 0 {
		d = 1
	}
	result := TrafficSnapshot{RXBytes: rx, TXBytes: tx, RXRate: float64(rx-t.prevRX) / d, TXRate: float64(tx-t.prevTX) / d}
	if result.RXRate > 0 || result.TXRate > 0 {
		t.lastActive = now
		t.lastRXRate, t.lastTXRate = result.RXRate, result.TXRate
	} else if now.Sub(t.lastActive) < 2*time.Second {
		result.RXRate, result.TXRate = t.lastRXRate, t.lastTXRate
	}
	t.prev, t.prevRX, t.prevTX = now, rx, tx
	return result
}
