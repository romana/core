package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	search "github.com/romana/contrib/rsearch"
)

func main() {
	var cfgFile = flag.String("c", "", "Kubernetes reverse search config file")
	var server = flag.Bool("server-mode", false, "Start a server")
	var host = flag.String("host", "", "Host for client to connect to")
	var proto = flag.String("protocol", "", "Protocol to use for client connect to")
	var port = flag.String("port", "", "TCP port for client to connect to")
	var searchTag = flag.String("r", "", "Search resources by tag")
	flag.Parse()

	done := make(chan search.Done)

	config, err := search.NewConfig(*cfgFile)
	if err != nil {
		log.Fatalf("Can not read config file %s, %s\n", *cfgFile, err)
	}

	if *host != "" {
		config.Server.Host = *host
	}

	if *proto != "" {
		config.Server.Proto = *proto
	}

	if *port != "" {
		config.Server.Port = *port
	}

	if *server {

	} else if len(*searchTag) > 0 {
		if config.Server.Debug {
			log.Println("Making request to the server")
		}
		r := search.SearchResource(config, search.SearchRequest{Tag: *searchTag})
		response, err := json.Marshal(r)
		if err != nil {
			log.Fatal("Failed to parse out server response, ", err)
		}
		fmt.Println(string(response))
	} else {
		log.Fatal("Either -s or -r must be given")
	}
}
