package main

import (
	"log"
	"testing"
	"time"
)

func TestMetaLink(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
		return
	}
	metaActiveList = make(map[int]map[string]int)
	metaFailureList = make(map[string]int)
	go MetaGobble("wss://stats.REDACTED.edu/gobble/post", "metagobbletester")
	time.Sleep(time.Second)
	log.Println("Gonna update.")
	metaUpdate(0, map[string]int{"192.168.1.1:443": 1})
	time.Sleep(time.Second * 10)
	log.Println("update should have happened.")
}
