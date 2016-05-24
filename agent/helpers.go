// Copyright (c) 2016 Pani Networks
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

package agent

// Description of Helper struct in mocks.go.

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	utilexec "github.com/romana/core/pkg/util/exec"
	utilos "github.com/romana/core/pkg/util/os"
)

// NewAgentHelper returns Helper with initialized default implementations
// for all interfaces.
func NewAgentHelper(agent *Agent) Helper {
	helper := new(Helper)
	helper.Executor = new(utilexec.DefaultExecutor)
	helper.OS = new(utilos.DefaultOS)
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

// createRoute creates IP route, returns nil if success and error otherwise.
func (h Helper) createRoute(ip net.IP, netmask string, via string, dest string, extraArgs ...string) error {
	log.Print("Helper: creating route")
	cmd := "/sbin/ip"
	targetIP := fmt.Sprintf("%s/%v", ip, netmask)
	args := []string{"ro", "add", targetIP, via, dest}
	args = append(args, extraArgs...)
	if _, err := h.Executor.Exec(cmd, args); err != nil {
		return shelloutError(err, cmd, args)
	}
	return nil // success
}

// ensureRouteToEndpoint verifies that ip route to endpoint interface exists, creates it otherwise.
// Error if failed, nil if success.
func (h Helper) ensureRouteToEndpoint(netif *NetIf) error {
	mask := fmt.Sprintf("%d", h.Agent.networkConfig.EndpointNetmaskSize())
	log.Print("Ensuring routes for ", netif.IP, " ", netif.Name)
	log.Print("Acquiring mutex ensureRouteToEndpoint")
	h.ensureRouteToEndpointMutex.Lock()
	defer func() {
		log.Print("Releasing mutex ensureRouteToEndpoint")
		h.ensureRouteToEndpointMutex.Unlock()
	}()
	log.Print("Acquired mutex ensureRouteToEndpoint")
	// If route not exist
	if err := h.isRouteExist(netif.IP, mask); err != nil {

		// Create route
		via := "dev"
		dest := netif.Name

		err := h.createRoute(netif.IP, mask, via, dest, "src", h.Agent.networkConfig.romanaGW.String())
		if err != nil {
			return netIfRouteCreateError(err, *netif)
		}
	}
	return nil
}

// isLineInFile reads a file and looks for specified string in file.
// Returns true if line found in file and flase otherwise.
func (h Helper) isLineInFile(path string, token string) (bool, error) {
	file, err := h.OS.Open(path)
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

// appendLineToFile appends a string to a file.
// TODO ensure we're getting a new line if there is no '\n' at EOF
func (h *Helper) appendLineToFile(path string, token string) error {
	file, err := h.OS.AppendFile(path)
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

// ensureLine ensures that line is present in a file.
func (h Helper) ensureLine(path string, token string) error {
	// if file exist
	if err := h.OS.CreateIfMissing(path); err != nil {
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

// ensureInterHostRoutes ensures we have routes to every other host.
func (h Helper) ensureInterHostRoutes() error {
	log.Print("Acquiring mutex ensureInterhostRoutes")
	h.ensureInterHostRoutesMutex.Lock()
	defer func() {
		log.Print("Releasing mutex ensureInterhostRoutes")
		h.ensureInterHostRoutesMutex.Unlock()
	}()
	log.Print("Acquired mutex ensureInterhostRoutes")

	via := "via"
	log.Printf("In ensureInterHostRoutes over %v\n", h.Agent.networkConfig.otherHosts)
	for _, host := range h.Agent.networkConfig.otherHosts {
		log.Printf("In ensureInterHostRoutes ensuring route for %v\n", host)
		_, romanaCidr, err := net.ParseCIDR(host.RomanaIp)
		if err != nil {
			return failedToParseOtherHosts(host.RomanaIp)
		}
		romanaMaskInt, _ := romanaCidr.Mask.Size()
		romanaMask := fmt.Sprintf("%d", romanaMaskInt)
		dest := host.Ip

		// wait until no one messing with routes
		// If route doesn't exist yet
		if err := h.isRouteExist(romanaCidr.IP, romanaMask); err != nil {

			// Create it
			err2 := h.createRoute(romanaCidr.IP, romanaMask, via, dest)
			if err2 != nil {
				return routeCreateError(err, romanaCidr.IP.String(), romanaMask, dest)
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
