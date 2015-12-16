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

// firewall_test.go contains test cases for firewall.go
package common

// Some comments on use of mocking framework in helpers_test.go.

import (
	"errors"
	"log"
	"net"
	"testing"
)

type netIf struct {
	Name string `form:"interface_name"`
	Mac  string `form:"mac_address"`
	IP   net.IP `form:"ip_address"`
}

func (netif *netIf) SetIP(ip string) error {

	netif.IP = net.ParseIP(ip)
	log.Printf("Setting IP: %s: %s\n", ip, netif.IP)
	if netif.IP == nil {
		return errors.New("Error")
	}
	return nil
}

// TestFormMarshaling tests marshaling/unmarshaling to/from HTML form.
func TestFormMarshaling(t *testing.T) {
	form := "mac_address=aa:bb:cc:dd:ee:ff&ip_address=10.0.1.4&interface_name=eth0"
	netIf := &netIf{}
	m := formMarshaller{}
	err := m.Unmarshal([]byte(form), netIf)
	log.Printf("Got Mac %s, Name %s IP %s\n", netIf.Mac, netIf.Name, netIf.IP)
	if err != nil {
		panic(err.Error())
	}
	if netIf.Name != "eth0" {
		t.Fail()
	}
	if netIf.Mac != "aa:bb:cc:dd:ee:ff" {
		t.Fail()
	}

	formByte, err := m.Marshal(netIf)
	if err != nil {
		panic(err.Error())
	}
	formStr := string(formByte)
	log.Printf("Got %s\n", formStr)
	if formStr != "interface_name=eth0&mac_address=aa:bb:cc:dd:ee:ff&ip_address=10.0.1.4" {
		t.Fail()
	}

}
