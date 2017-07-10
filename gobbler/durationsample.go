package main

import (
	"log"
	"math/rand"
	"time"

	"github.com/orcaman/concurrent-map"
	metrics "github.com/rcrowley/go-metrics"
)

const HistogramSampleMaxSize = 512

// DurationSample tracks active events, producing a statistical report of
// current durations.
type DurationSample struct {
	values cmap.ConcurrentMap
}

type sampleValue struct {
	Start time.Time
	What  string
}

// NewDurationSample makes a new DurationSample
func NewDurationSample() *DurationSample {
	v := &DurationSample{}
	v.values = cmap.New()
	return v
}

// Start begins tracking a new event
func (d *DurationSample) Start(session string, decoy string) {
	d.values.Set(session, sampleValue{time.Now(), decoy})
}

// End marks that an event has completed
func (d *DurationSample) End(session string) string {
	if val, exists := d.values.Pop(session); exists {
		return val.(sampleValue).What
	}
	return ""
}

// Stats creates a gometrics sample of the currently tracked durations.
func (d *DurationSample) Stats() metrics.Sample {
	if d.values == nil {
		log.Println("Unexpected call to stats on uninitialized log!")
		return metrics.NewSampleSnapshot(0, []int64{})
	}
	values := d.values.Items()
	c := len(values)
	keys := make([]string, 0, c)
	for k := range values {
		keys = append(keys, k)
	}
	if c > HistogramSampleMaxSize {
		c = HistogramSampleMaxSize
	}
	perm := rand.Perm(len(keys))

	items := make([]int64, c)
	now := time.Now()

	for i := 0; i < c; i++ {
		key := keys[perm[i]]
		item := values[key]

		items[i] = int64(now.Sub(item.(sampleValue).Start))
	}
	return metrics.NewSampleSnapshot(int64(len(items)), items)
}
