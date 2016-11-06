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

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"github.com/pborman/uuid"
	"io/ioutil"
	"sync/atomic"

	"log"
	"os"
	"reflect"
	"runtime/debug"
	"strings"
	"sync"
)

const (
	DefaultTestConfigFile = "../common/testdata/romana.sample.yaml"
)

var once sync.Once

// Holds environment variables
var environ map[string]string

// Environ is similar to os.Environ() but
// returning environment as a map instead of an
// array of strings.
func Environ() map[string]string {
	once.Do(initEnviron)
	return environ
}

func initEnviron() {
	environ = make(map[string]string)
	for _, kv := range os.Environ() {
		keyValue := strings.Split(kv, "=")
		environ[keyValue[0]] = keyValue[1]
	}
}

// RomanaTestSuite holds state for use in testing.
type RomanaTestSuite struct {
	tmpFiles   []string
	ConfigFile string
	Config     Config
}

// MockConfig will take the config file specified
// and mock things up, by:
// 1. Replacing all ports with 0 (making the services use ephemeral ports)
// 2. Replacing all database instance names with the result of GetMockDbName
//    and write it out to /tmp/romana.yaml
func (rts *RomanaTestSuite) MockConfig(romanaConfigFile string) error {
	log.Printf("MockConfig():")
	overrideConfigFile := os.ExpandEnv("${ROMANA_CONFIG_FILE}")
	if overrideConfigFile != "" {
		log.Printf("\tOverriding %s with value of ROMANA_CONFIG_FILE: %s", romanaConfigFile, overrideConfigFile)
		romanaConfigFile = overrideConfigFile
	}
	log.Printf("\tWill use config file %s", romanaConfigFile)
	var err error
	location := GetCaller()
	log.Printf("\tCalled from %s", location)
	config, err := ReadConfig(romanaConfigFile)
	if err != nil {
		return err
	}
	services := []string{"root", "topology", "ipam", "agent", "tenant", "policy"}

	for _, svc := range services {
		svcConfig := config.Services[svc]
		log.Printf("\tMocking for service %s:", svc)
		svcConfig.Common.Api.Port = 0
		if svc != "root" {
			storeConfig := svcConfig.ServiceSpecific["store"].(map[string]interface{})
			if storeConfig["type"] == "sqlite3" {
				sqliteFile := rts.GetMockSqliteFile(svc)
				storeConfig["database"] = sqliteFile
			} else {
				// For now it's just mysql
				// TODO add this to RomanaTestSuite list of resources to destroy
				storeConfig["database"] = GetMockDbName(svc)
			}
			log.Printf("\t\tDB config: %v", storeConfig["database"])
		}
	}

	outFile := fmt.Sprintf("/tmp/romana_%s.yaml", getUniqueMockNameComponent())
	err = WriteConfig(config, outFile)
	if err != nil {
		log.Printf("\tRead %s, trying to write %s: %v", romanaConfigFile, outFile, err)
		return err
	}
	wrote, _ := ioutil.ReadFile(outFile)
	rts.Config, err = ReadConfig(outFile)
	if err != nil {
		return err
	}
	rts.ConfigFile = outFile
	log.Printf("\tRead %s, wrote to %s:\n%s\n------------------------", romanaConfigFile, outFile, string(wrote))
	return nil
}

func (rts *RomanaTestSuite) CleanUp() {
	log.Printf("CleanUp(): Cleaning up the following temporary files: %v", rts.tmpFiles)
	for _, f := range rts.tmpFiles {
		err := os.Remove(f)
		if err == nil {
			log.Printf("CleanUp(): Removed %s.", f)
		} else {
			log.Printf("CleanUp(): Failed removing %s: %v", f, err)
		}
	}
}

func (rts *RomanaTestSuite) GetMockSqliteFile(svc string) string {
	fname := fmt.Sprintf("/var/tmp/%s.sqlite3", GetMockDbName(svc))
	rts.tmpFiles = append(rts.tmpFiles, fname)
	return fname
}

var (
	mockSeqNum  = int64(0)
	mockSeqLock sync.Mutex
)

func SqlNullStringUuid() sql.NullString {
	return sql.NullString{String: uuid.New(), Valid: true}
}

// IsZeroValue checks whether the provided value is equal to the
// zero value for the type. Zero values would be:
//  - 0 for numeric types
//  - "" for strings
//  - uninitialized struct for a struct
//  - zero-size for a slice or a map
func IsZeroValue(val interface{}) bool {
	valType := reflect.TypeOf(val)
	valKind := valType.Kind()
	if valKind == reflect.Slice || valKind == reflect.Map {
		valVal := reflect.ValueOf(val)
		return valVal.Len() == 0
	}
	zeroVal := reflect.Zero(valType).Interface()
	//	log.Printf("Zero value of %+v (type %T, kind %s) is %+v", val, val, valKind, zeroVal)
	return val == zeroVal
}

// CleanURL is similar to path.Clean() but to work on URLs
func CleanURL(url string) (string, error) {
	elements := strings.Split(url, "/")
	retval := ""
	if len(elements) < 3 {
		return "", errors.New("Invalid URL")
	}
	retval = elements[0] + "//" + elements[2]
	if len(elements) == 3 {
		return retval, nil
	}
	for i := 3; i < len(elements); i++ {
		if elements[i] == "" {
			continue
		}
		retval += "/" + elements[i]
	}
	return retval, nil
}

func PressEnterToContinue() {
	fmt.Println("Press ENTER to continue")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
}

// getUniqueMockNameComponent creates a string that can be used as a part of
// a name of a resource (e.g., file, DB name, etc) that is unique.
// It is of the form <PID>_<SEQ>_<UUID>, where
// - SEQ gets is next number in the sequence
// - UUID is normalized to remove dashes.
func getUniqueMockNameComponent() string {
	atomic.AddInt64(&mockSeqNum, 1)
	uuid := strings.Replace(uuid.New(), "-", "", -1)
	return fmt.Sprintf("%d_%d_%s", os.Getpid(), mockSeqNum, uuid)
}

// GetMockDbName creates a DB name as follows:
// <SERVICE_NAME>_<Result of getUniqueMockNameComponent()>
func GetMockDbName(svc string) string {
	return fmt.Sprintf("%s_%s", svc, getUniqueMockNameComponent())
}

// GetCaller2 is similar to GetCaller but goes up the specified
// number of frames.
func GetCaller2(up int) string {
	stackLines := strings.Split(string(debug.Stack()), "\n")
	location := "Unknown"

	// Given that each frame takes up 2 lines, this is the breakdown:
	// 0-1: debug.Stack()
	// 2-3: GetCaller (this method)
	// 4-5: Method that called GetCaller
	// 6-7: Information we are looking for
	cnt := 8 + up*2
	if len(stackLines) > cnt {
		location = strings.TrimSpace(stackLines[cnt])
	}
	return location
}

// GetCaller returns the location information of the caller of
// the method that invoked GetCaller.
func GetCaller() string {
	return GetCaller2(1)
}

// toBool is a convenience function that's like ParseBool
// but allows also "on"/"off" values.
func ToBool(val string) (bool, error) {
	s := strings.ToLower(val)
	switch s {
	case "yes":
		return true, nil
	case "on":
		return true, nil
	case "y":
		return true, nil
	case "true":
		return true, nil
	case "t":
		return true, nil
	case "1":
		return true, nil
	case "enabled":
		return true, nil
	case "no":
		return false, nil
	case "off":
		return false, nil
	case "n":
		return false, nil
	case "false":
		return false, nil
	case "f":
		return false, nil
	case "0":
		return false, nil
	case "disabled":
		return false, nil
	}
	return false, errors.New(fmt.Sprintf("Cannot convert %s to boolean", val))
}

func MkMap() map[string]interface{} {
	return make(map[string]interface{})
}

func MkMapStr() map[string]string {
	return make(map[string]string)
}

// KeyValue represents a key-value pair (similar to Java's Map.Entry)
type KeyValue struct {
	Key   string
	Value interface{}
}

// KV is a convenience function to create a KeyValue
// value.
func KV(key string, value interface{}) KeyValue {
	return KeyValue{Key: key, Value: value}
}

func InitMap(keyValuePairs ...KeyValue) map[string]interface{} {
	m := MkMap()
	for _, entry := range keyValuePairs {
		m[entry.Key] = entry.Value
	}
	return m
}

// In returns true if needle is found in haystack.
func In(needle string, haystack []string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
