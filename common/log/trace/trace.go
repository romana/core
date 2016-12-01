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

package trace

// These definitions are just helpful conventions for our use of trace
// messages. There is no 'standard' for logging trace levels, but for our
// projects we use them as described below.

const (
	Public  int = 1 // Messages on entry of public/exported functions
	Private         // Messages on entry of private/non-exported functions
	Inside          // Messages from inside of functions
)
