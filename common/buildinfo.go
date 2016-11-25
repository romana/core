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

package common

// Build information support.

import (
	"fmt"
)

// Build Information and Timestamp.
// Pass build information to the executable using go run as below:
//
// go run -ldflags \
// "-X github.com/romana/kube/common.buildInfo=`git describe --always` \
// -X github.com/romana/kube/common.buildTimeStamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'`" \
// main.go -version
//
// or using go build as below:
//
// go build -ldflags \
// "-X github.com/romana/kube/common.buildInfo=`git describe --always` \
// -X github.com/romana/kube/common.buildTimeStamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'`" \
// main.go
//
var buildInfo = "No Build Information Provided"
var buildTimeStamp = "No Build Time Provided"

// BuildInfo return build revision and time string.
func BuildInfo() string {
	return fmt.Sprintf("Build Revision: %s\nBuild Time: %s", buildInfo, buildTimeStamp)
}
