// Copyright (c) 2016 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Package util contains common utility functions.
package util

import (
	"bytes"
	"encoding/json"
	"fmt"

	cli "github.com/spf13/cobra"
)

// UsageError shows command line help for errors caused due
// to few or more arguments being passed to the commands or
// sub-commands of romana command line tools.
func UsageError(cmd *cli.Command, format string, args ...interface{}) error {
	return fmt.Errorf("%s\nCheck '%s -h' for help",
		fmt.Sprintf(format, args...),
		cmd.CommandPath())
}

// JSONIndent indents the JSON input string, return input string if it fails.
func JSONIndent(inStr string) string {
	var out bytes.Buffer
	err := json.Indent(&out, []byte(inStr), "", "\t")
	if err != nil {
		return inStr
	}
	return out.String()
}
