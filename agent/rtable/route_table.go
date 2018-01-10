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

package rtable

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"

	"github.com/pkg/errors"
	"github.com/romana/rlog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	RT_TABLES_FILE = "/etc/iproute2/rt_tables"
)

// EnsureRouteTableExist verifies that romana route table with appropriate index
// exist in RT_TABLES_FILE file.
func EnsureRouteTableExist(routeTableId int) (err error) {

	file, err := os.OpenFile(RT_TABLES_FILE, os.O_RDWR, 0644)
	if err != nil {
		return errors.Wrapf(err,
			"failed to open file %s to ensure that romana table name is configured",
			RT_TABLES_FILE)
	}
	defer func() {
		if err2 := file.Close(); err2 != nil {
			err = errors.Wrapf(err, "couldn't close the file %s", err)
		}
	}()

	tableName := "romana"
	err = ensureRouteTableName(file, tableName, routeTableId)
	if err != nil {
		return errors.Wrap(err, "couldn't verify that romana table name is configured")
	}
	return nil

}

func ensureRouteTableName(file *os.File, tableName string, routeTableId int) error {
	targetEntry := fmt.Sprintf("%d %s", routeTableId, tableName)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() == targetEntry {
			return nil
		}
	}

	_, err := file.Write([]byte(targetEntry + "\n"))
	if err != nil {
		return err
	}

	return nil
}

// nlRuleHandle subset of netlink.Handle methods isolated for mocking.
type nlRuleHandle interface {
	RuleList(family int) ([]netlink.Rule, error)
	RuleAdd(*netlink.Rule) error
}

// EnsureRomanaRouteRule verifies that rule for romana routing table installed.
func EnsureRomanaRouteRule(romanaRouteTableId int, nl nlRuleHandle) error {
	rules, err := nl.RuleList(unix.AF_INET)
	if err != nil {
		return err
	}

	for _, rule := range rules {
		if rule.Table == romanaRouteTableId {
			return nil
		}
	}

	inRule := netlink.NewRule()
	inRule.Table = romanaRouteTableId

	rlog.Infof("Adding routing rule %v", inRule)
	err = nl.RuleAdd(inRule)
	if err != nil {
		return err
	}

	return nil
}

// FlushRomanaTable attempts to delete all routes from table called romana.
func FlushRomanaTable() error {
	command := exec.Command("ip", "ro", "flush", "table", "romana")

	out, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to flush romana route table out=%s, err=%s", string(out), err)
	}

	return nil

}
