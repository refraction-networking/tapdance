package main

import (
	"testing"
	"time"
)

func TestDuration(t *testing.T) {
	dur := NewDurationSample()
	dur.Start("x", "")
	dur.Start("y", "")
	dur.Start("z", "test")
	dur.Start("a", "")
	time.Sleep(time.Millisecond * 10)
	m := dur.Stats().Mean()
	if m > float64(time.Millisecond*15) || m < float64(time.Millisecond*5) {
		t.Fatal("Stats incorrect.")
	}
	if dur.End("z") != "test" {
		t.Fatal("ending fails recall")
	}
	if dur.End("a") != "" {
		t.Fatal("ending fails recall!")
	}
	dur.Start("b", "")
	dur.Start("c", "")
	time.Sleep(time.Millisecond * 10)
	n := dur.Stats().Max()
	if n < int64(time.Millisecond*15) {
		t.Fatal("long lived sessions forgotten")
	}
	n = dur.Stats().Min()
	if n > int64(time.Millisecond*15) {
		t.Fatal("subsequent sessions not added")
	}
}

func BenchmarkStats1k(b *testing.B) {
	dur := NewDurationSample()
	for i := 0; i < 1024; i += 1 {
		dur.Start("192.168.1.1", "192.168.1.1")
	}
	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		s := dur.Stats()
		_ = s.Percentiles([]float64{0.5, 0.75})
	}
}

func BenchmarkStats10k(b *testing.B) {
	dur := NewDurationSample()
	for i := 0; i < 1024*10; i += 1 {
		dur.Start("192.168.1.1", "192.168.1.1")
	}
	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		s := dur.Stats()
		_ = s.Percentiles([]float64{0.5, 0.75})
	}
}
