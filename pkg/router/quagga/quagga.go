// Copyright (c) 2017 Pani Networks
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

// The package  advertises list of networks by connecting to the instance
// of bgpd and executing `networl A.B.C.D/E` command for every network in
// a list.
package quagga

import (
	"bufio"
	"bytes"
	"fmt"
	telnet "github.com/reiver/go-telnet"
	router "github.com/romana/core/pkg/router/publisher"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

func New(config router.Config) (router.Interface, error) {
	quagga := QuaggaBgpRoutePublisher{}

	quagga.BgpdHost = config.SetDefault("bgpdHost", "localhost")
	quagga.BgpdPort = config.SetDefault("bgpdPort", "2605")
	quagga.UserPrompt = config.SetDefault("userPrompt", "bgpd> ")
	quagga.AdminPrompt = config.SetDefault("adminPrompt", "bgpd# ")
	quagga.ConfigPrompt = config.SetDefault("configPrompt", "bgpd(config)# ")
	quagga.RouterPrompt = config.SetDefault("routerPrompt", "bgpd(config-router)# ")

	if pass, ok := config["password"]; ok {
		quagga.Password = pass
	} else {
		return nil, fmt.Errorf("Parameter missing `password`")
	}

	if enable, ok := config["enablePass"]; ok {
		quagga.EnablePass = enable
	} else {
		return nil, fmt.Errorf("Parameter missing `enablePass`")
	}

	if localAS, ok := config["localAS"]; ok {
		quagga.LocalAS = localAS
	} else {
		return nil, fmt.Errorf("Parameter missing `localAS`")
	}

	if debug, ok := config["debug"]; ok && debug != "false" {
		quagga.Debug = true
	}

	return quagga, nil
}

// Default implementation of Interface that publishes routes via instance
// of bgpd managed by quagga.
type QuaggaBgpRoutePublisher struct {
	// Connect to BGP
	sync.Mutex

	// IP address or hostname bgpd listens on.
	BgpdHost string

	// bgpd port (defaul 2605)
	BgpdPort string

	// Quagga password. Required.
	Password string

	// Enable privilege password. Required.
	EnablePass string

	// User prompt to expect in telnet session. Optional.
	UserPrompt string

	// Admin prompt to expect in telnet session. Optional
	AdminPrompt string

	// Config prompt to expect in telnet session. Optional.
	ConfigPrompt string

	// Router prompt to expect in a telnet session. Optional.
	RouterPrompt string

	// LocalAS used to identify proper config context in bgpd
	// `router bgp .LocalAS`. Required.
	LocalAS string

	// Extra output
	Debug bool

	// Internal.
	Input bytes.Buffer

	networks []net.IPNet
}

// Update implements Interact, it publishes provided networks with
// quagga managed bgp.
func (q QuaggaBgpRoutePublisher) Update(networks []net.IPNet) error {
	q.Lock()
	defer q.Unlock()
	log.Printf("Starting bgp update at %s:%s", q.BgpdHost, q.BgpdPort)

	q.networks = networks
	q.Input.Reset()
	telnet.DialToAndCall(fmt.Sprintf("%s:%s", q.BgpdHost, q.BgpdPort), q)

	log.Printf("Finished bgp update at %s:%s", q.BgpdHost, q.BgpdPort)
	return nil
}

func (q QuaggaBgpRoutePublisher) debug(format string, args ...interface{}) {
	if q.Debug {
		log.Printf(format, args...)
	}
}

// CallTELNET implements telnet.Caller interface, this is a callback that gets called by telnet package.
func (caller QuaggaBgpRoutePublisher) CallTELNET(ctx telnet.Context, writer telnet.Writer, reader telnet.Reader) {
	var bufferArray [1]byte
	buffer := bufferArray[:]

	go func(reader io.Reader) {
		for {
			// Read 1 byte, if read zero then skip
			// if error, thenm break.
			n, err := reader.Read(buffer)
			if n <= 0 && err == nil {
				continue
			} else if n <= 0 && err != nil {
				break
			}

			caller.Input.Write(buffer)

			if caller.Debug {
				os.Stdout.Write(buffer)
			}
		}
	}(reader)

	time.Sleep(time.Duration(1 * time.Second))

	if bytes.HasSuffix(caller.Input.Bytes(), []byte("Password: ")) {
		err := caller.Authentificate(writer)
		if err != nil {
			log.Printf("Error: when authentificating %s", err)
			return
		}
	}

	showConfigCmd := "show running-config\n"
	_, err := writer.Write([]byte(showConfigCmd))
	if err != nil {
		log.Printf("Error when writing %s: %s", showConfigCmd, err)
		return
	}

	time.Sleep(time.Duration(1 * time.Second))

	// make a map of networks and their desired statuses
	networks := make(map[string]string)
	for _, network := range caller.parseCurrentNetworks() {
		networks[network] = "remove"
	}

	for _, network := range caller.networks {
		newNetwork := network.String()
		if _, ok := networks[newNetwork]; ok {
			networks[newNetwork] = "keep"
		} else {
			networks[newNetwork] = "add"
		}
	}

	// turn map of statuses into lists by status
	// ignore "keep" status
	var addedNetworks, outdatedNetworks []string
	for network, status := range networks {
		if status == "add" {
			addedNetworks = append(addedNetworks, network)
		} else if status == "remove" {
			outdatedNetworks = append(outdatedNetworks, network)
		}
	}

	caller.debug("Networks to add %v, networks to delete %v", addedNetworks, outdatedNetworks)

	err = caller.configMode(writer)
	if err != nil {
		log.Printf("Error: %s", err)
		return
	}

	err = caller.updateAdvertisedNetworks(addedNetworks, outdatedNetworks, writer)
	if err != nil {
		log.Printf("Error: %s", err)
		return
	}

	return
}

func (caller *QuaggaBgpRoutePublisher) updateAdvertisedNetworks(addedNetworks, outdatedNetworks []string, writer telnet.Writer) error {
	var commands []interactCmd

	for _, network := range outdatedNetworks {
		commands = append(commands, interactCmd{
			send:   fmt.Sprintf("no network %s\n", network),
			expect: caller.RouterPrompt,
		})
	}

	for _, network := range addedNetworks {
		commands = append(commands, interactCmd{
			send:   fmt.Sprintf("network %s\n", network),
			expect: caller.RouterPrompt,
		})
	}

	commands = append(commands, interactCmd{
		send:   "write file\n",
		expect: caller.RouterPrompt,
	})

	err := caller.Interact(commands, writer)
	if err != nil {
		return fmt.Errorf("Failed to update advertised networks, err=(%s)", err)
	}

	return nil
}

func (caller *QuaggaBgpRoutePublisher) shutdownTelnet(writer telnet.Writer) error {
	commands := []interactCmd{
		{
			send:   "exit\n",
			expect: caller.ConfigPrompt,
		}, {
			send:   "exit\n",
			expect: caller.AdminPrompt,
		}, {
			send:   "exit\n",
			expect: "",
		},
	}

	err := caller.Interact(commands, writer)
	if err != nil {
		return fmt.Errorf("Failed to shutdown telnet session properly, err=(%s)", err)
	}

	return nil
}

func (caller *QuaggaBgpRoutePublisher) Authentificate(writer telnet.Writer) error {
	commands := []interactCmd{
		{
			fmt.Sprintf("%s\n", caller.Password),
			caller.UserPrompt,
		}, {
			"enable\n",
			"Password: ",
		}, {
			fmt.Sprintf("%s\n", caller.EnablePass),
			caller.AdminPrompt,
		},
	}
	err := caller.Interact(commands, writer)
	if err != nil {
		return fmt.Errorf("Authentification failed, err=(%s)", err)
	}

	return nil
}

func (caller *QuaggaBgpRoutePublisher) configMode(writer telnet.Writer) error {
	commands := []interactCmd{
		{
			"configure terminal\n",
			caller.ConfigPrompt,
		}, {
			fmt.Sprintf("router bgp %s\n", caller.LocalAS),
			caller.RouterPrompt,
		},
	}

	err := caller.Interact(commands, writer)
	if err != nil {
		return fmt.Errorf("Config mode failed, err=(%s)", err)
	}

	return nil
}

// parseCurrentNetworks goes through current input buffer and returns
// a list of advertised networks.
func (caller *QuaggaBgpRoutePublisher) parseCurrentNetworks() []string {
	var nets []string
	scanner := bufio.NewScanner(&caller.Input)
	for scanner.Scan() {
		line := scanner.Bytes()
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte("network")) {
			words := bytes.Split(line, []byte{' '})
			nets = append(nets, string(words[len(words)-1]))
		}
	}

	return nets
}

type interactCmd struct {
	send   string
	expect string
}

func (caller *QuaggaBgpRoutePublisher) Interact(commands []interactCmd, writer telnet.Writer) error {
	for _, command := range commands {
		n, err := writer.Write([]byte(command.send))
		if err != nil || n != len(command.send) {
			// TODO, remove passwords from error message
			return fmt.Errorf("interaction attempted to write %s, wrote %d out of %d chars, err=%s",
				command.send,
				n,
				len(command.send),
				err)
		}

		time.Sleep(time.Duration(1 * time.Second))
		if !bytes.HasSuffix(caller.Input.Bytes(), []byte(command.expect)) {
			return fmt.Errorf("interaction expected output %s, got %s",
				command.expect,
				caller.Input.Bytes()[caller.Input.Len()-len(command.expect):])
		}

	}

	return nil

}
