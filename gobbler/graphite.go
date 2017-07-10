package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// graphiteBuffer is how long the buffer in the channel can be - so how much
// sychronizing needs to occur between the io thread and the network thread.
const graphiteBuffer = 10

// Graphite reports graphite metrics at an interval of 'd'
func Graphite(prefix string) chan core_msg {
	reports := make(chan core_msg, graphiteBuffer)
	go report(prefix, reports)
	return reports
}

type stat struct {
	name  string
	value float64
}

func tryParseFloat(str string) float64 {
	ret, _ := strconv.ParseFloat(str, 64)
	return ret
}

func tryParseInt(str string) int64 {
	ret, _ := strconv.ParseInt(str, 10, 64)
	return ret
}

var openSessions = int64(0)
var openStreams = int64(0)
var aggToClient = int64(0)
var aggToCovert = int64(0)
var decoysfailed = int64(0)
var sessionswithfailures = int64(0)

func parse(msg string, core int) ([]stat, int64, int64) {
	trimed := strings.TrimSuffix(msg, "\n")
	split := strings.Split(trimed, " ")
	if split[0] == "status" {
		// Status messages
		if len(split) < 16 {
			return []stat{}, 0, 0
		}
		stats := make([]stat, 13)
		stats[0] = stat{name: "elligator_checks", value: tryParseFloat(split[1])}
		stats[1] = stat{name: "packets", value: tryParseFloat(split[2])}
		stats[2] = stat{name: "tls_packets", value: tryParseFloat(split[3])}
		stats[3] = stat{name: "bytes", value: tryParseFloat(split[4])}
		stats[4] = stat{name: "cpu_usecs", value: tryParseFloat(split[5])}
		stats[5] = stat{name: "mem_used", value: tryParseFloat(split[8])}
		stats[6] = stat{name: "reconnects", value: tryParseFloat(split[9])}
		stats[7] = stat{name: "tracked_flows", value: tryParseFloat(split[10])}
		stats[8] = stat{name: "active_sessions", value: tryParseFloat(split[11])}
		stats[9] = stat{name: "bytes_443", value: tryParseFloat(split[12])}
		stats[10] = stat{name: "syns_443", value: tryParseFloat(split[13])}
		stats[11] = stat{name: "user_upload", value: tryParseFloat(split[14])}
		stats[12] = stat{name: "user_download", value: tryParseFloat(split[15])}

		timestamp := tryParseInt(split[6])
		duration := tryParseInt(split[7])
		return stats, timestamp, duration
	} else if split[0] == "drop" {
		if len(split) < 3 {
			return []stat{}, 0, 0
		}
		// Dropped packets
		stats := make([]stat, 2)
		stats[0] = stat{name: "delta_drop", value: tryParseFloat(split[1])}
		stats[1] = stat{name: "total_drop", value: tryParseFloat(split[2])}

		return stats, time.Now().Unix(), 0
	} else if split[0] == "error" {
		if len(split) < 3 {
			return []stat{}, 0, 0
		}
		stats := make([]stat, 1)
		stats[0] = stat{name: "error." + split[2], value: float64(1)}
		return stats, time.Now().Unix(), 0
	} else if split[0] == "activedecoys" || trimed == "activedecoys" {
		sessions := make(map[string]int)
		total := 0
		for _, decoy := range split[1:] {
			parts := strings.Split(decoy, "@")
			sessions[parts[1]] = int(tryParseInt(parts[0]))
			total += sessions[parts[1]]
		}
		metaUpdate(core, sessions)
		stats := make([]stat, 2)
		stats[0] = stat{name: "activedecoys", value: float64(len(split[1:]))}
		stats[1] = stat{name: "activeclients", value: float64(total)}
		return stats, time.Now().Unix(), 0
	} else if split[0] == "faileddecoys" {
		if len(split) < 2 {
			return []stat{}, 0, 0
		}
		stats := make([]stat, 2)
		decoysfailed += int64(metaFail(split[1:]))
		sessionswithfailures++
		stats[0] = stat{name: "decoysfailed", value: float64(decoysfailed)}
		stats[1] = stat{name: "sessionswithfailures", value: float64(sessionswithfailures)}
		return stats, time.Now().Unix(), 0
	} else if trimed == "reset" {
		return []stat{}, 0, 0
	} else {
		fmt.Fprintf(os.Stderr, "Could not parse core message: %s\n", trimed)
		return []stat{}, 0, 0
	}
}

func report(prefix string, lines chan core_msg) error {
	conn, err := tls.Dial("tcp", "REDACTED.edu:443", &tls.Config{})
	if err != nil {
		log.Printf("Failed to connect: %v", err)
		return err
	}
	defer conn.Close()

	w := bufio.NewWriter(conn)
	for {
		select {
		case line := <-lines:
			stats, stamp, timerange := parse(line.msg, line.core)
			for _, stat := range stats {
				fmt.Fprintf(w, "%s.%d.%s.count %f %d\n", prefix, line.core, stat.name, stat.value, stamp)
				if timerange > 0 {
					fmt.Fprintf(w, "%s.%d.%s.count_ps %.2f %d\n", prefix, line.core,
						stat.name, float64(stat.value*1000000000.0)/float64(timerange), stamp)
				}
			}
		}
		err := w.Flush()
		if err != nil {
			log.Printf("Failed to write: %v", err)
			// Reconnect on errors.
			conn.Close()
			conn, _ = tls.Dial("tcp", "REDACTED.edu:443", &tls.Config{})
			w = bufio.NewWriter(conn)
		}
	}
}
