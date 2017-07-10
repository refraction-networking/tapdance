package main

import (
	"fmt"
	"github.com/hpcloud/tail"
	"strconv"
	"strings"
	"time"
)

type core_msg struct {
	t    time.Time
	core int
	msg  string
}

func parseTime(layout string, s string) time.Time {
	ts_split := strings.Split(s, ".")
	t, _ := time.Parse(layout, ts_split[0])
	ns, _ := strconv.ParseInt(ts_split[1], 10, 64)

	return time.Unix(t.Unix(), ns*1000)
}

func readGobbler(gob_log chan core_msg) {
	t, _ := tail.TailFile("/var/log/tapdance/gobbler/current", tail.Config{
		Follow: true,
		ReOpen: true})
	for line := range t.Lines {
		// 2017/07/05 23:54:57.783063 Core 4: delstream 4ece91d3346c2653184d016d975f4958 225466 14654
		split := strings.SplitN(line.Text, " Core ", 2)
		if len(split) < 2 {
			continue
		}
		ts := split[0]
		t := parseTime("2006/02/01 15:04:05", ts)
		rest := strings.SplitN(split[1], ": ", 2)
		if len(rest) < 2 {
			continue
		}
		core, err := strconv.Atoi(rest[0])
		if err != nil {
			continue
		}

		gob_log <- core_msg{t, core, rest[1]}
	}
}

func readTapdance(td_log chan core_msg) {
	t, _ := tail.TailFile("/var/log/tapdance/current", tail.Config{
		Follow: true,
		ReOpen: true})
	for line := range t.Lines {
		if strings.Contains(line.Text, "DEBUG: ") {
			// May 07, 2017 23:12:36.505206 (Core 7) DEBUG: newsession 8fafaa60f0379a5afa6c9ca245b3f97b R.R.R.R:37368 -> R.R.R.
			split := strings.SplitN(line.Text, " (Core ", 2)
			if len(split) < 2 {
				continue
			}
			ts := split[0]
			t := parseTime("Jan 02, 2006 15:04:05", ts)
			rest := strings.SplitN(split[1], ") ", 2)
			if len(rest) < 2 {
				continue
			}
			core, err := strconv.Atoi(rest[0])
			if err != nil {
				continue
			}
			msg := rest[1][7:] // "DEBUG: newstream ....
			td_log <- core_msg{t, core, msg}
		}
		//fmt.Println(line.Text)
	}

}

func main() {
	td_log := make(chan core_msg)
	gob_log := make(chan core_msg)

	go readTapdance(td_log)
	go readGobbler(gob_log)

	t_fmt := "Jan 02, 2006 15:04:05.000000"
	n_cores := 12

	seen_logs := make([]map[string]core_msg, n_cores)
	for i := 0; i < n_cores; i++ {
		seen_logs[i] = make(map[string]core_msg)
	}

	for {
		select {
		case log := <-td_log:
			prev_log, ok := seen_logs[log.core][log.msg]
			if ok {
				fmt.Printf("Tap: %s Core %d: %s\n", log.t.Format(t_fmt), log.core, log.msg)
				fmt.Printf("   -%d ms\n", log.t.Sub(prev_log.t)/time.Millisecond)
				delete(seen_logs[log.core], log.msg)
			} else {
				seen_logs[log.core][log.msg] = log
			}
		case log := <-gob_log:
			prev_log, ok := seen_logs[log.core][log.msg]
			if ok {
				// Behind
				fmt.Printf("Gob: %s Core %d: %s\n", log.t.Format(t_fmt), log.core, log.msg)
				if !strings.Contains(log.msg, "drop 0 ") {
					fmt.Printf("   +%d ms\n", log.t.Sub(prev_log.t)/time.Millisecond)
				}
				delete(seen_logs[log.core], log.msg)
			} else {
				seen_logs[log.core][log.msg] = log
			}
		}

	}
}
