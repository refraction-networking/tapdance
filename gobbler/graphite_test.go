package main

import (
	"strings"
	"testing"
	"time"
)

func TestGraphite(t *testing.T) {
	testchan := Graphite("tapdance.testing")
	testchan <- core_msg{core: 0, msg: "0 0 0 0 1 0\n"}
}

func TestSample(t *testing.T) {
	re := make(chan core_msg, 10)

	time.Sleep(50 * time.Millisecond)
	n := <-re
	if strings.Split(n.msg, " ")[0] != "activesession" {
		t.Fatal("unexpected log")
	}
}
