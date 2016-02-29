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

package common

type Role interface {
	Name() string
}

type role struct {
	name string
}

type Authenticator interface {
	Authenticate(user string, password string)  (Role, error)
}

type TokenAuthenticator struct {
	
}

// Represents the type of credential (e.g., certificate, 
// username-password, etc.
type CredentialType string

const (
	CredentialUsernamePassword = "userPass"
	CredentialNone = "none"
)

// Container for various credentials. Currently containing Username/Password
// but keys, certificates, etc. can be used in the future. 
type Credential struct {
	Type CredentialType
	Username string
	Password string
}

// MakeCredentialFromCliArgs takes all possible CLI
// arguments that can be provided and constructs appropriate
// Credential structure. This is just keeping in one
// method a common functionality that will be in every
// command.
func MakeCredentialFromCliArgs(username string, password string) Credential {
	if username == nil {
		return Credential{CredentialType:CredentialNone}, nil
	} else {
		return Credential{CredentialType: CredentialUsernamePassword, Username: username, Password: password}
	}
}

// Authenticate method here fulfills the Authenticate() method of common.AuthDb interface.
func (ta *TokenAuthenticator) Authenticate(user string, password string) ([]common.Role, error) {
	gormDb := rootStore.DbStore.Db
	whereClause = fmt.Sprintf("username = ? AND password = %s", rootStore.DbStore.GetPasswordFunction())
	var roles []Role
	gormDb.Table("role").Select("role.name").Joins("JOIN user_roles ON role.id = user_roles.role_id JOIN users ON users.id = user_roles.user_id").Where(whereClause, username, password).Find(roles)
	err := common.MakeMultiError(tenantStore.DbStore.Db.GetErrors())
	if err != nil {
		return nil, err
	}
	return roles, nil
}