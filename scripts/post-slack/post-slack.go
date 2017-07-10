// simple hack to post things to the slack channel
//
// snipped out of the gobbler and given a commandline
//
// TODO: should take the URL and credentials from a config
// file (or the commandline) instead of having them baked in.

package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
)

func main() {

    var hostname string
    var failure error

    if len(os.Args) != 2 {
	fmt.Println("Error: incorrect usage")
	fmt.Println("Usage:", os.Args[0], "msg")
	os.Exit(1)
    }

    hostname, failure = os.Hostname()
    if failure != nil {
	// Use IP address instead?
	hostname = "UnknownHost"
    }

    msg := os.Args[1]

    slack_obj := map[string]string{
	    "username" : "gobbler",
	    "text" : "post-slack on " + hostname + " says: " + msg,
	    "link_names" : "1",
    }
    post_msg, _ := json.Marshal(slack_obj)

    url := "https://hooks.slack.com/services/REDACTED/REDACTED/REDACTED"
    fmt.Println("NOT PRINTING TO SLACK DUE TO REDACTED KEY")
    _, failure = http.Post(url, "application/json", bytes.NewBuffer(post_msg))
    if failure != nil {
	fmt.Println("Failed to post to slack", failure)
	os.Exit(1)
    } else {
	os.Exit(0)
    }
}
