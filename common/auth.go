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

// Authentication-related code.

package common

import (
	"flag"
	"fmt"
	cli "github.com/spf13/cobra"
	config "github.com/spf13/viper"
	"golang.org/x/crypto/ssh/terminal"
	"syscall"
)

type Role interface {
	Name() string
}

type role struct {
	name string
}

// Represents the type of credential (e.g., certificate,
// username-password, etc.)
type CredentialType string

const (
	CredentialUsernamePassword = "userPass"
	CredentialNone             = "none"

	UsernameKey = "ROMANA_USERNAME"
	PasswordKey = "ROMANA_PASSWORD"
)

// Container for various credentials. Currently containing Username/Password
// but keys, certificates, etc. can be used in the future.
type Credential struct {
	Type CredentialType
	cmd  *cli.Command
	// In case of usage with Cobra (https://github.com/spf13/cobra/)
	// no need to check
	assumeFlagParsed bool
	Username         string
	Password         string
	userFlag         string
	passFlag         string
}

func NewCredentialCobra(cmd *cli.Command) *Credential {
	cred := &Credential{cmd: cmd, assumeFlagParsed: true}
	cmd.PersistentFlags().StringVarP(&cred.userFlag, "username", "u", "", "Username")
	cmd.PersistentFlags().StringVarP(&cred.passFlag, "password", "", "", "Password")
	return cred
}

func NewCredential(flagSet *flag.FlagSet) *Credential {
	cred := &Credential{}
	//	glog.Infof("XXX Adding username to flagset %P", flagSet)
	flagSet.StringVar(&cred.userFlag, "username", "", "Username")
	flagSet.StringVar(&cred.passFlag, "password", "", "Password")
	config.SetDefault(UsernameKey, "")
	config.SetDefault(PasswordKey, "")
	return cred
}

// GetPasswd gets password from stdin.
func GetPasswd() (string, error) {
	fmt.Print("Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	password := string(bytePassword)
	return password, nil
}

// Initialize constructs appropriate Credential structure based on
// provided data, which includes, in the following precedence (later
// superseding earlier):
// * In case of username/password auth:
//   1. As keys UsernameKey and PasswordKey in ~/.romana.yaml file
//   2. As environment variables whose names are UsernameKey and PasswordKey values
//   3. As --username and --password command-line flags.
//      If --username flag is specified but --password flag is omitted,
//      the user will be prompted for the password.
// Notes:
// 1. The first two precedence steps (~/.romana.yaml and environment variables)
//    are taken care by the config module (github.com/spf13/viper)
// 2. If flag.Parsed() is false at the time of this call, the command-line values are
//    ignored.
//
func (c *Credential) Initialize() error {
	username := config.GetString(UsernameKey)
	password := config.GetString(PasswordKey)
	if c.assumeFlagParsed || flag.Parsed() {
		if c.userFlag != "" {
			username = c.userFlag
			if c.passFlag == "" {
				// Ask for password
				var err error
				password, err = GetPasswd()
				if err != nil {
					return err
				}
			} else {
				password = c.passFlag
			}
		}
	}
	if username != "" {
		//
		c.Username = username
		c.Password = password
		c.Type = CredentialUsernamePassword
	} else {
		// For now, credential is None if not specified
		c.Type = CredentialNone
	}
	return nil
}
