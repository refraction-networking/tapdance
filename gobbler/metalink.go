package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// This file handles functions associated with maintaining a connection to
// the meta gobbler. sending data on changes to number of decoys in use,
// and receiving updates about decoys that shouldn't be used anymore.

// Keep the following two structs in sync with metagobber/routes.go

// GobblerMessage is the format of messages sent from gobbler to metagobbler
type GobblerMessage struct {
	StationName   string
	ActiveDecoys  map[string]int
	FailingDecoys map[string]int
}

// MetaGobblerMessage is the format of messages sent from metagobbler to gobblers.
type MetaGobblerMessage struct {
	OverloadedDecoys []string
}

var metaGobbleAuth = "REDACTEDUSERNAME:REDACTEDPASSWORD"

var metaGobbleConn *websocket.Conn

var metaFailureList map[string]int
var metaActiveList map[int]map[string]int
var metaItem GobblerMessage
var metaMutex sync.Mutex

// MetaGobble manages a connection to the metagobbler.
func MetaGobble(url, hostname string) {
	startedLoop := false
	for {
		header := make(http.Header)
		header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(metaGobbleAuth)))
		conn, _, err := websocket.DefaultDialer.Dial(url, header)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't dial meta gobbler: %v", err)
			time.Sleep(time.Second)
			continue
		}
		metaGobbleConn = conn
		metaItem.StationName = hostname
		if !startedLoop {
			go metaSendLoop()
			startedLoop = true
		}

		incoming := MetaGobblerMessage{}
		recentBad := 0
		for {
			err := conn.ReadJSON(&incoming)
			if websocket.IsCloseError(err) {
				break
			} else if err != nil {
				recentBad++
				if recentBad > 5 {
					break
				}
			} else {
				recentBad = 0
			}
			log.Println("Attempting update to overloaded decoys file.")
			log.Printf("Current number of overloaded decoys: %d\n", len(incoming.OverloadedDecoys))
			ioutil.WriteFile("/var/lib/tapdance/overloaded_decoys", []byte(strings.Join(incoming.OverloadedDecoys, "\n")), 0644)
			// signal tapdance
			err = exec.Command("/usr/bin/killall", "-SIGUSR2", "zc_tapdance").Run()
			if err != nil {
				log.Printf("Poking failed: %v\n", err)
			}
		}
	}
}

func metaFail(ipdecoys []string) int {
	// format #@ip,sni
	metaMutex.Lock()
	total := 0
	for i := 0; i < len(ipdecoys); i += 1 {
		parts := strings.Split(ipdecoys[i], "@")
		n := tryParseInt(parts[0])
		metaFailureList[parts[1]] += int(n)
		total += int(n)
	}
	metaMutex.Unlock()
	return total
}

func metaUpdate(core int, newList map[string]int) {
	metaMutex.Lock()
	metaActiveList[core] = newList
	metaMutex.Unlock()
}

func metaSendLoop() {
	after := time.Tick(time.Second)
	for _ = range after {
		metaItem.ActiveDecoys = make(map[string]int)
		metaItem.FailingDecoys = make(map[string]int)
		metaMutex.Lock()
		for _, m := range metaActiveList {
			for k, v := range m {
				metaItem.ActiveDecoys[k] += v
			}
		}
		for k, v := range metaFailureList {
			metaItem.FailingDecoys[k] = v
		}
		metaFailureList = make(map[string]int)
		metaMutex.Unlock()

		metaGobbleConn.WriteJSON(metaItem)
	}
}
