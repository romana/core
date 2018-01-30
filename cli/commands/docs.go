// Copyright (c) 2018 Pani Networks
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

// Package commands contains various files for adding commands and subcommands
// to romana command line tools.
//
// Each file in the package directory contains exactly one command and
// multiple sub-commands for it, except the root.go file which initializes
// the config and cli package and sets various command line parameters.
//
// The package used for configuration is called viper and it allows
// configuration to be read from configuration files or to be set from
// command line parameters.
//
// The package used for command line interface is called cobra and it
// is the main library behind providing usage, flag support and various
// other command line features.
//
package commands
