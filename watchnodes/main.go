// Copyright (c) 2016 Pani Networks Inc
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Package main contains a subset of listener functionality where
// it connects to kubernetes using kubernetes client-go and watches
// node creation/deletion events and then adds/deletes the nodes
// to/from romana cluster appropriately.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"time"

	"github.com/romana/core/common"

	config "github.com/spf13/viper"
	"k8s.io/client-go/1.5/kubernetes"
	"k8s.io/client-go/1.5/pkg/api"
	"k8s.io/client-go/1.5/pkg/api/v1"
	"k8s.io/client-go/1.5/pkg/fields"
	"k8s.io/client-go/1.5/tools/cache"
	"k8s.io/client-go/1.5/tools/clientcmd"
)

func main() {
	// Accept a kubernetes config file of try the default location.
	var kubeConfig = flag.String("kubeconfig", os.Getenv("HOME")+"/.kube/config",
		"Kubernetes config file.")
	var romanaConfig = flag.String("romanaconfig", os.Getenv("HOME")+"/.romana.yaml",
		"Romana config file.")
	version := flag.Bool("version", false, "Build Information.")
	flag.Parse()

	if *version {
		fmt.Println(common.BuildInfo())
		return
	}

	if *kubeConfig == "" {
		log.Println("Error: must have kubernetes config files specified.")
		os.Exit(1)
	}

	if err := initConfig(*romanaConfig); err != nil {
		log.Println("Error reading romana config file: ", err)
		os.Exit(1)
	}

	// Since romana config was successful above, now set rootURL from config.
	setRomanaRootURL()

	// Try generating config for kubernetes client-go from flags passed,
	// so that we can connect to kubernetes using them.
	kConfig, err := clientcmd.BuildConfigFromFlags("", *kubeConfig)
	if err != nil {
		log.Println("Error: ", err.Error())
		os.Exit(1)
	}

	// Get a set of REST clients which connect to kubernetes services
	// from the config generated above.
	restClientSet, err := kubernetes.NewForConfig(kConfig)
	if err != nil {
		log.Println("Error: ", err.Error())
		os.Exit(1)
	}

	// Channel for stopping watching node events.
	stop := make(chan struct{}, 1)

	// nodeWatcher is a new ListWatch object created from the specified
	// restClientSet above for watching node events.
	nodeWatcher := cache.NewListWatchFromClient(
		restClientSet.CoreClient,
		"nodes",
		api.NamespaceAll,
		fields.Everything())

	// Setup a notifications for specific events using NewInformer.
	_, nodeInformer := cache.NewInformer(
		nodeWatcher,
		&v1.Node{},
		time.Minute,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    kubernetesAddNodeEventHandler,
			UpdateFunc: kubernetesUpdateNodeEventHandler,
			DeleteFunc: kubernetesDeleteNodeEventHandler,
		},
	)

	log.Println("Starting receving node events.")
	go nodeInformer.Run(stop)

	// Set up channel on which to send signal notifications.
	// We must use a buffered channel or risk missing the signal
	// if we're not ready to receive when the signal is sent.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// Block until a signal is received.
	<-c

	// Stop watching node events.
	close(stop)
	log.Println("Stopped watching node events and quitting watchnodes.")
}

// kubernetesAddNodeEventHandler is called when Kubernetes reports an
// add-node event It connects to the Romana REST API and adds the node
// to the Romana cluster.
func kubernetesAddNodeEventHandler(n interface{}) {
	node, ok := n.(*v1.Node)
	if !ok {
		log.Printf("Error processing Add Event received for node(%s) ", n)
		return
	}

	log.Printf("Add Event received for node(%s, %s, %d) ",
		node.Name, node.Status.Addresses, len(node.Status.Addresses))

	if err := romanaHostAdd(node); err != nil {
		log.Printf("Error processing Add Event received for node(%s): %s",
			node.Name, err)
		return
	}

	log.Printf("Node (%s) successful added to romana cluster.", node.Name)
}

// kubernetesUpdateNodeEventHandler currently doesn't do anything yet.
// TODO: If node shows up with new IP or romana CIDR,
//       then accommodate it if possible.
func kubernetesUpdateNodeEventHandler(o, n interface{}) {
	// node, ok := n.(*v1.Node)
	_, ok := n.(*v1.Node)
	if !ok {
		log.Printf("Error processing Update Event received for node(%s) ", n)
		return
	}

	// Disable this for now, update events are sent every
	// 10 seconds per node, thus this could fill up the log
	// easily in very small amount of time.
	// log.Printf("Update Event received for node(%s) ",node.Name)
}

// kubernetesDeleteNodeEventHandler is called when Kubernetes reports a
// delete-node event It connects to the Romana REST API and deletes the
// node from the Romana cluster.
func kubernetesDeleteNodeEventHandler(n interface{}) {
	node, ok := n.(*v1.Node)
	if !ok {
		log.Printf("Error processing Delete Event received for node(%s) ", n)
		return
	}

	log.Printf("Delete Event received for node(%s, %s) ",
		node.Name, node.Status.Addresses)

	if err := romanaHostRemove(node.Name); err != nil {
		log.Printf("Error processing Delete Event received for node(%s) ",
			node.Name)
		return
	}
}

// romanaHostAdd connects to romana API and adds a node to
// the romana cluster.
func romanaHostAdd(node *v1.Node) error {
	if node.Name == "" || len(node.Status.Addresses) < 1 {
		log.Printf("Error: received invalid host name or IP Address: (%s)", node)
		return errors.New("Error: received invalid host name or IP Address.")
	}
	hostname := node.Name
	hostIP := node.Status.Addresses[0].Address

	rootURL := config.GetString("RootURL")

	client, err := common.NewRestClient(common.GetDefaultRestClientConfig(rootURL))
	if err != nil {
		return err
	}

	topologyURL, err := client.GetServiceUrl("topology")
	if err != nil {
		return err
	}

	index := common.IndexResponse{}
	err = client.Get(topologyURL, &index)
	if err != nil {
		return err
	}

	host := common.Host{
		Name: hostname,
		Ip:   hostIP,
	}

	data := common.Host{}
	err = client.Post(topologyURL+"/hosts", host, &data)
	if err != nil {
		log.Printf("Error adding host (%s).\n", hostname)
		return err
	}

	log.Printf("Host (%s) added successfully.\n", hostname)
	return nil
}

func romanaHostRemove(host string) error {
	log.Printf("Unimplemented: Remove a host(%s).", host)
	return nil
}

// setRomanaRootURL sanitizes rootURL and rootPort and also
// sets baseURL which is needed to connect to other romana
// services.
func setRomanaRootURL() {
	// Variables used for configuration and flags.
	var baseURL string
	var rootURL string
	var rootPort string

	// Add port details to rootURL else try localhost
	// if nothing is given on command line or config.
	rootURL = config.GetString("RootURL")
	rootPort = config.GetString("RootPort")
	if rootPort == "" {
		re, _ := regexp.Compile(`:\d+/?`)
		port := re.FindString(rootURL)
		port = strings.TrimPrefix(port, ":")
		port = strings.TrimSuffix(port, "/")
		if port != "" {
			rootPort = port
		} else {
			rootPort = "9600"
		}
	}
	config.Set("RootPort", rootPort)
	if rootURL != "" {
		baseURL = strings.TrimSuffix(rootURL, "/")
		baseURL = strings.TrimSuffix(baseURL, ":9600")
		baseURL = strings.TrimSuffix(baseURL, ":"+rootPort)
	} else {
		baseURL = "http://localhost"
	}
	config.Set("BaseURL", baseURL)
	rootURL = baseURL + ":" + rootPort + "/"
	config.Set("RootURL", rootURL)
}

// initConfig reads in config file and ENV variables if set.
func initConfig(file string) error {
	if file == "" {
		config.SetConfigName(".romana") // name of config file (without extension)
		config.AddConfigPath("$HOME")   // adding home directory as first search path
	} else {
		config.SetConfigFile(file)    // name of config file
		config.AddConfigPath("$HOME") // adding home directory as first search path
	}
	config.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	err := config.ReadInConfig()
	if err != nil {
		log.Println("Error using config file:", config.ConfigFileUsed())
		return err
	}

	log.Println("Using config file:", config.ConfigFileUsed())
	return nil
}
