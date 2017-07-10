package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type core_msg struct {
	core int
	msg  string
}

// status $elligator_checks $packets $tls_packets $bytes $cpu_usecs
type core_status struct {
	set            bool      // If this is initailized or not
	time           time.Time // last time this core was updated
	reported_death bool      // True if this core is dead and we've already reported it (reset on Init)
	core           int
	// Stats:
	elligator_checks int64
	packets          int64
	tls_packets      int64
	bytes            int64
	cpu_usecs        int64
}

// This class aggregates status. When the last status is .add()ed
// (count == len(statuses)), it aggregates all the statuses and prints
// out the result
type Aggregator struct {
	time         time.Time // Initialized time (will be used at print out)
	unique_count int       // Number of unique core statuses we have aggregated
	count        int       // Number of core statuses we've seen without printing
	dead_cores   int       // Number of cores that we have reported dead since last Init/Reset
	is_prod      bool      // True if we're running in production mode
	statuses     []core_status
}

func (a *Aggregator) Add(core int, msg string) {
	trimed := strings.TrimSuffix(msg, "\n")
	split := strings.Split(trimed, " ")
	if len(split) < 6 {
		return
	}
	a.statuses[core].elligator_checks, _ = strconv.ParseInt(split[1], 10, 64)
	a.statuses[core].packets, _ = strconv.ParseInt(split[2], 10, 64)
	a.statuses[core].tls_packets, _ = strconv.ParseInt(split[3], 10, 64)
	a.statuses[core].bytes, _ = strconv.ParseInt(split[4], 10, 64)
	a.statuses[core].cpu_usecs, _ = strconv.ParseInt(split[5], 10, 64)
	a.statuses[core].time = time.Now()

	if !a.statuses[core].set {
		a.statuses[core].set = true
		a.unique_count += 1
	}
	a.count += 1

	if a.unique_count == len(a.statuses) {
		// Print the aggregate
		total := core_status{}
		for i := 0; i < a.unique_count; i++ {
			total.elligator_checks += a.statuses[i].elligator_checks
			total.packets += a.statuses[i].packets
			total.tls_packets += a.statuses[i].tls_packets
			total.bytes += a.statuses[i].bytes
			total.cpu_usecs += a.statuses[i].cpu_usecs
		}
		diff := time.Since(a.time).Nanoseconds()
		log.Println(fmt.Sprintf("STATUS %d checks/sec, %d pkts/sec (%d tls pkts/sec) %d Mbps",
			(int64(total.elligator_checks)*1000000000)/diff,
			(int64(total.packets)*1000000000)/diff,
			(int64(total.tls_packets)*1000000000)/diff,
			(int64(total.bytes)*8000)/diff))

		if a.dead_cores > 0 {
			// Hey, we're back
			if a.is_prod {
				post_to_slack("All cores back online")
			}
		}
		// Clear this aggregator
		a.Reset()
	} else {
		a.CheckDeadCores()
	}
}

func (a *Aggregator) Init(n_cores int, is_prod bool) {
	a.time = time.Now()
	a.unique_count = 0
	a.count = 0
	a.dead_cores = 0
	a.is_prod = is_prod
	a.statuses = make([]core_status, n_cores)
}

func (a *Aggregator) Reset() {
	a.Init(len(a.statuses), a.is_prod)
}

func (a *Aggregator) CheckDeadCores() {
	if a.count > 2*len(a.statuses) || time.Since(a.time) > 30*time.Second {
		// Find out which one
		for i := 0; i < len(a.statuses); i++ {
			if a.statuses[i].reported_death {
				continue
			}
			if !a.statuses[i].set || time.Since(a.statuses[i].time) > 30*time.Second {
				// This core is dead!
				a.dead_cores += 1

				// Report to slack if we are in production mode
				if a.is_prod {
					post_to_slack(fmt.Sprintf("@channel Core %d died!!! %d cores down", i, a.dead_cores))
					a.statuses[i].reported_death = true
				}
			}
		}
	}
}

func gobble_core(core int, verbose bool, is_prod bool, msgs chan core_msg) {
	for {
		if verbose {
			log.Println(fmt.Sprintf("Waiting for core %d to open fifo...", core))
		}
		f, err := os.Open("/tmp/tapdance-reporter-" + strconv.Itoa(core) + ".fifo")
		if err != nil {
			panic(err)
		}
		if verbose {
			log.Println(fmt.Sprintf("Core %d opened", core))
		}

		reader := bufio.NewReader(f)
		var more bool
		for err == nil {
			var buf []byte
			more = true
			for more {
				var tmp []byte
				tmp, more, err = reader.ReadLine()
				if err != nil {
					break
				}
				buf = append(buf, tmp...)
			}

			if len(buf) > 0 {
				msgs <- core_msg{core, string(buf) + "\n"}
			}
		}

		if verbose {
			log.Println(fmt.Sprintf("Core %d closed", core))
			if is_prod {
				post_to_slack(fmt.Sprintf("Core %d closed the FIFO!!!", core))
			}
		}
	}
}

func post_to_slack(msg string) {
	log.Println("SLACK MSG: ", msg)
	slack_obj := map[string]string{
		"username": "gobbler", "text": hostname + ": " + msg, "link_names": "1"}
	post_msg, _ := json.Marshal(slack_obj)

    log.Println("SLACK POSTING KEY REDACTED; NOT POSTING TO SLACK!")
	// url := "https://hooks.slack.com/services/REDACTED/REDACTED/REDACTED"
	// _, err := http.Post(url, "application/json", bytes.NewBuffer(post_msg))
	// if err != nil {
	// 	log.Println("Failed to post to Slack: ", err)
	// }
}

var Agg *Aggregator

var hostname string

func main() {

	is_prod := flag.Bool("prod", false, "Set if running in production (posts to slack)")
	n_cores := flag.Int("cores", 4, "Number of cores to expect")
	meta_url := flag.String("metagobbler", "wss://stats.REDACTED.edu/gobble2/post", "URL to report to metagobbler")
	flag.Parse()

	var failure error
	hostname, failure = os.Hostname()
	if failure != nil {
		// Use IP address instead?
		hostname = "UnknownHost"
	}

	graphite := Graphite("tapdance.gobbler." + hostname)

	metaActiveList = make(map[int]map[string]int)
	metaFailureList = make(map[string]int)
	go MetaGobble(*meta_url, hostname)

	if *is_prod {
		post_to_slack("Starting gobbler")
	}

	msgs := make(chan core_msg)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	for i := 0; i < *n_cores; i++ {
		go gobble_core(i, true, *is_prod, msgs)
	}

	Agg = new(Aggregator)
	Agg.Init(*n_cores, *is_prod)

	// Check for dead cores every so often
	for {
		select {
		case cmsg := <-msgs:
			graphite <- cmsg
			time_s := time.Now().Format("2006/02/01 15:04:05.000000")
			fmt.Printf("%s Core %d: %s", time_s, cmsg.core, cmsg.msg)
			if strings.HasPrefix(cmsg.msg, "status ") {
				Agg.Add(cmsg.core, cmsg.msg)
			}
		case <-time.After(5 * time.Second):
			Agg.CheckDeadCores()
		}
	}
}
