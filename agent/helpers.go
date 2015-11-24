// Copyright (c) 2015 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
package agent

// This file contains Helper methods used mostly used to interact with OS
// together with some auxiliary functions.

// Description of Helper struct in mocks.go.

import (
	"bufio"
	"fmt"
	"github.com/romana/core/common"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// NewAgentHelper returns Helper with initialized default implementations
// for all interfaces.
func NewAgentHelper(agent *Agent) Helper {
	helper := new(Helper)
	helper.Executor = new(DefaultExecutor)
	helper.OS = new(DefaultOS)
	helper.Agent = agent
	helper.ensureLineMutex = &sync.Mutex{}
	helper.ensureRouteToEndpointMutex = &sync.Mutex{}
	helper.ensureInterHostRoutesMutex = &sync.Mutex{}
	return *helper
}

// sendSighup is attempting to send SIGHUP signal to the process.
// TODO Maybe mock os. and proc.
func (h Helper) sendSighup(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		return err
	}
	return nil
}

// DhcpPid function checks if dnsmasq is running, it returns pid on succes
// or error otherwise.
// TODO Only works with single daemon, maybe implement support for more.
func (h Helper) DhcpPid() (int, error) {
	cmd := "ps"
	args := []string{"-C", "dnsmasq-calico", "-o", "pid", "--no-headers"}
	out, err := h.Executor.Exec(cmd, args)
	if err != nil {
		return -1, shelloutError(err, cmd, args)
	}

	// TODO Deal with list of pids coming in from shellout
	// this will just fail.
	pid, err := strconv.Atoi(strings.Trim(string(out), " \n"))
	// TODO Improve sanity check, we want to be sure that we're on to our
	// dnsmasq and not some other process which happened to match our search.
	if pid > 65535 || pid < 1 || err != nil {
		return pid, shelloutError(err, cmd, args)
	}
	return pid, nil
}

// isRouteExist checks if route exists, returns nil if it is and error otherwise.
// Idea is - `ip ro show A.B.C.D/M` will came up empty if route does not exist.
func (h Helper) isRouteExist(ip net.IP, netmask string) error {
	cmd := "/sbin/ip"
	target := fmt.Sprintf("%s/%v", ip, netmask)
	args := []string{"ro", "show", target}
	out, err := h.Executor.Exec(cmd, args)
	if err != nil {
		return shelloutError(err, cmd, args)
	}

	if l := len(out); l > 0 {
		return nil // success
	}

	return noSuchRouteError()
}

// createRoute Creates IP route, returns nil if success and error otherwise.
func (h Helper) createRoute(ip net.IP, netmask string, via string, dest string) error {
	log.Print("Helper: creating route")
	cmd := "/sbin/ip"
	targetIP := fmt.Sprintf("%s/%v", ip, netmask)
	args := []string{"ro", "add", targetIP, via, dest}
	if _, err := h.Executor.Exec(cmd, args); err != nil {
		return shelloutError(err, cmd, args)
	}
	return nil // success
}

// ensureRouteToEndpoint verifies that ip route to endpoint interface exists, creates it otherwise.
// Error if failed, nil if success.
func (h Helper) ensureRouteToEndpoint(netif *NetIf) error {
	mask := fmt.Sprintf("%d", h.Agent.networkConfig.EndpointNetmask())
	log.Print("Ensuring routes for ", netif.Ip, " ", netif.Name)
	log.Print("Acquiring mutex ensureRouteToEndpoint")
	h.ensureRouteToEndpointMutex.Lock()
	defer func() {
		log.Print("Releasing mutex ensureRouteToEndpoint")
		h.ensureRouteToEndpointMutex.Unlock()
	}()
	log.Print("Acquired mutex ensureRouteToEndpoint")
	// If route not exist
	if err := h.isRouteExist(netif.Ip, mask); err != nil {

		// Create route
		via := "dev"
		dest := netif.Name

		if err := h.createRoute(netif.Ip,
			mask, via, dest); err != nil {

			// Or report error
			return netIfRouteCreateError(err, *netif)
		}
	}
	return nil
}

// isLineInFile reads a file and looks for specified string in file.
// Returns true if line found in file and flase otherwise.
func (h Helper) isLineInFile(path string, token string) (bool, error) {
	file, err := h.OS.open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, token) {
			file.Close()
			return true, nil
		}
	}
	file.Close()
	return false, nil
}

// appendLineToFile is a method that appends a string to a file.
func (h *Helper) appendLineToFile(path string, token string) error {
	file, err := h.OS.appendFile(path)
	if err != nil {
		return err
	}

	defer file.Close()
	t := []byte(fmt.Sprintf("%s\n", token))
	_, err = file.Write(t)
	if err != nil {
		return err
	}
	return nil
}

// ensureLine is a method which ensures that line is present in a file.
func (h Helper) ensureLine(path string, token string) error {
	// if file exist
	if err := h.OS.createIfMissing(path); err != nil {
		return ensureLineError(err)
	}

	// wait until no one using the file
	log.Print("Acquiring mutex ensureLine")
	h.ensureLineMutex.Lock()
	defer func() {
		log.Print("Releasing mutex ensureLine")
		h.ensureLineMutex.Unlock()
	}()
	log.Print("Acquired mutex ensureLine")
	lineInFile, err := h.isLineInFile(path, token)
	if err != nil {
		return ensureLineError(err)
	}

	// if line not in file yet
	if !lineInFile {
		// add line
		if err := h.appendLineToFile(path, token); err != nil {
			return ensureLineError(err)
		}
	}
	return nil
}

// otherHosts method builds array of hosts in pani setup other then
// ourselves, for the purposes of routing mainly.
func (h Helper) otherHosts() []common.HostMessage {
	index := h.Agent.networkConfig.currentHostIndex
	//	origin := h.Agent.config.PocConfig.DC.Leaves[0].Hosts
	// Should this keep querying the REST service every time?
	origin := h.Agent.networkConfig.hosts
	others := append(origin[:index], origin[index+1:]...)
	return others
}

// ensureInterHostRoutes method ensures we have routes to every other host.
func (h Helper) ensureInterHostRoutes() error {
	OtherHosts := h.otherHosts()
	for j := range OtherHosts {
		romanaIP, romanaCidr, err := net.ParseCIDR(OtherHosts[j].RomanaIp)
		if err != nil {
			return failedToParseOtherHosts(OtherHosts[j].RomanaIp)
		}
		//		romanaIP := romanaIP
		romanaMaskInt, _ := romanaCidr.Mask.Size()
		romanaMask := fmt.Sprintf("%d", romanaMaskInt)
		via := "via"
		dest := OtherHosts[j].Ip

		// wait until no one messing with routes
		log.Print("Acquiring mutex ensureInterhostRoutes")
		h.ensureInterHostRoutesMutex.Lock()
		defer func() {
			log.Print("Releasing mutex ensureInterhostRoutes")
			h.ensureInterHostRoutesMutex.Unlock()
		}()
		log.Print("Acquired mutex ensureInterhostRoutes")
		// If route doesn't exist yet
		if err := h.isRouteExist(romanaIP, romanaMask); err != nil {

			// Create it
			if err := h.createRoute(romanaIP, romanaMask, via, dest); err != nil {

				// Or report error
				return routeCreateError(err, romanaIP.String(), romanaMask, dest)
			}
		}
	}
	return nil
}

// waitForIface waits for network interface to become available in the system.
func (h Helper) waitForIface(expectedIface string) bool {
	for i := 0; i <= h.Agent.waitForIfaceTry; i++ {
		log.Printf("Helper: Waiting for interface %s, %d attempt", expectedIface, i)
		ifaceList, err := net.Interfaces()
		if err != nil {
			log.Println("Warning:Helper: failed to read net.Interfaces()")
		}
		for iface := range ifaceList {
			if ifaceList[iface].Name == expectedIface {
				return true
			}
		}
		time.Sleep(10 * time.Second)
	}
	return false
}
