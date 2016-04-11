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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
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

/* Test helpers -- from Negroni */
func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

func refute(t *testing.T, a interface{}, b interface{}) {
	if a == b {
		t.Errorf("Did not expect %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

func expect2(t *testing.T, msg string, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("%s: Expected %v (type %v) - Got %v (type %v)", msg, b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

func refute2(t *testing.T, msg string, a interface{}, b interface{}) {
	if a == b {
		t.Errorf("%s: Did not expect %v (type %v) - Got %v (type %v)", msg, b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

func TestToBool(t *testing.T) {
	yeses := []string{"YES", "y", "On", "1", "tRuE", "t"}
	nos := []string{"NO", "n", "Off", "0", "fALse", "f"}
	for i := range yeses {
		b, e := ToBool(yeses[i])
		if e != nil {
			t.Error(e)
		}
		expect(t, b, true)
	}
	for i := range nos {
		b, e := ToBool(nos[i])
		if e != nil {
			t.Error(e)
		}
		expect(t, b, false)
	}

}

// TestClientNoHost just tests that we don't hang forever
// when there is no host.
// TODO
// How about if this is an IP address, which is behind a firewall, so
// that all attempts to send a packet there fails, no RST or anything
// ever comes back? Do we wait the full TCP timeout?
func TestClientNoHost(t *testing.T) {
	client, err := NewRestClient("http://no.such.host.really", GetDefaultRestClientConfig())
	if err != nil {
		t.Error(err)
	}
	log.Println("Calling non-existent URL")
	resp := make(map[string]interface{})
	ts0 := time.Now()
	err = client.Get("/no/such/url", resp)
	if err == nil {
		t.Error(errors.New("No error!"))
	}
	elapsed := time.Since(ts0)
	// We do not really time out here because DNS lookup with timeout
	// would require something like lookupIPDeadline() from
	// https://golang.org/src/net/lookup.go, which has the following issues:
	// 1. Way too complicated to drag this into here
	// 2. Would need to change code to be smart about timeout on DNS
	// lookup and then on HTTP requests. On the other hand, that is
	// probably not an issue that much - for good hosts, we may just
	// exceed the total timeout this way once, or once every DNS cache
	// TTL. But in any case this seems like an overkill here.
	log.Printf("Time to look up non-existent DNS %d\n", elapsed)

	log.Println("Done")
}

// timeoutingHTTPServer mocks up an HTTP server that sleeps a
// specified number of milliseconds before returning a response.
type timeoutingHTTPServer struct{}

// ServeHTTP is the method to conform to Handler interface
// for timeoutingHTTPServer.
func (s timeoutingHTTPServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	tStr := string(req.Form.Get("t"))
	log.Printf("Parsing duration %s\n", tStr)
	millis, err := time.ParseDuration(tStr)
	if err != nil {
		io.WriteString(w, fmt.Sprintf("{ \"error\" : \"%s\" }", err.Error()))
		return
	}
	log.Printf("Will sleep for %s\n", millis)
	w.Header().Set("X-Test", tStr)
	time.Sleep(millis)
	io.WriteString(w, "{ \"hello\" : \"world\"}")
}

// timeoutService is a Romana Service used in tests.
type timeoutService struct{}

func (s timeoutService) SetConfig(config ServiceConfig) error {
	return nil
}

func (s timeoutService) Initialize() error {
	return nil
}

// Routes provides the following routes for the timeoutService:
// 1. /normal -- where the "hello world" response is written right
//               away (and we are testing the client's delayed reads/writes)
// 2. /sleepy -- where the query parameter "t" determines how long the
//               server should sleep before returning the "hello world" response
//               (we are testing the server's delayed reads/writes, see
//               below as TestSleepyServerTimeout).
func (s timeoutService) Routes() Routes {
	routes := Routes{
		Route{
			"GET",
			"/normal",
			func(input interface{}, ctx RestContext) (interface{}, error) {
				inp := input.(UnwrappedRestHandlerInput)
				writer := inp.ResponseWriter
				c, err := writer.Write([]byte("hello world"))
				log.Printf("/normal: Wrote output count %d, error %v, now is %v\n", c, err, time.Now())
				return nil, nil
			},
			func() interface{} {
				return http.Request{}
			},
			false,
			nil,
		},
		Route{
			"GET",
			"/sleepy",
			func(input interface{}, ctx RestContext) (interface{}, error) {
				inp := input.(UnwrappedRestHandlerInput)
				writer := inp.ResponseWriter
				req := inp.Request
				req.ParseForm()
				dur, _ := time.ParseDuration(req.Form.Get("t"))
				log.Printf("/sleepy: Sleeping for %v\n", dur)
				time.Sleep(dur)
				c, err := writer.Write([]byte("hello world"))
				log.Printf("/sleepy: Wrote output count %d, error %v, now is %v\n", c, err, time.Now())
				return nil, nil
			},
			func() interface{} {
				return http.Request{}
			},
			false,
			nil,
		},
	}
	return routes
}

func (s timeoutService) Name() string {
	return "mock"
}

const helloWorld = "hello world"

// TestSleepyServerTimeout will test server that sleeps --
// and either TimeoutHandler or read/write timeout would kick in.
func TestSleepyServerTimeout(t *testing.T) {
	cfg := &ServiceConfig{Common: CommonConfig{Api: &Api{Port: 0, RestTimeoutMillis: 100}}}
	log.Printf("Mock config: %v\n", cfg)
	svc := &timeoutService{}
	svcInfo, err := InitializeService(svc, *cfg)
	if err != nil {
		t.Error(err)
	}
	msg := <- svcInfo.Channel
	log.Printf("Service says %s\n", msg)

	times := []int{80, 90, 110, 120}
	for i := range times {
		millis := times[i]
		client := http.Client{}
		url := fmt.Sprintf("http://%s/sleepy?t=%dms", svcInfo.Address, millis)
		log.Printf("Calling %s\n", url)
		req, _ := http.NewRequest("GET", url, nil)
		resp, err := client.Do(req)
		var body []byte
		if millis < 100 {
			expect2(t, fmt.Sprintf("Expected no error for timeout %d", millis), err, nil)
			body, err = ioutil.ReadAll(resp.Body)
			expect2(t, fmt.Sprintf("Expected no error for timeout %d", millis), err, nil)
			resp.Body.Close()
		}
		log.Printf("%v: Got %s\n", time.Now(), string(body))
		if millis < 100 {
			expect(t, string(body), helloWorld)
		} else {
			bodyStr := string(body)
			if bodyStr != TimeoutMessage && bodyStr != "" {
				t.Errorf("Expected %s or nothing, got %s", TimeoutMessage, bodyStr)
			}
		}
	}
}

// This tests purely read/write timeout.
func TestNormalServerTimeout(t *testing.T) {
	cfg := &ServiceConfig{Common: CommonConfig{Api: &Api{Port: 0, RestTimeoutMillis: 100}}}
	log.Printf("Mock config: %v\n", cfg)
	svc := &timeoutService{}
	svcInfo, err := InitializeService(svc, *cfg)
	if err != nil {
		t.Error(err)
	}
	msg := <-svcInfo.Channel
	log.Printf("Service says %s\n", msg)

	times := []int{90, 95, 120, 150}
	for i := range times {
		millis := times[i]
		timeout, _ := time.ParseDuration(fmt.Sprintf("%dms", millis))
		conn, err := net.Dial("tcp", svcInfo.Address)
		if err != nil {
			t.Error(err)
		}
		time.Sleep(timeout)
		fmt.Fprintf(conn, "GET /normal HTTP/1.0\r\n\r\n")
		rdr := bufio.NewReader(conn)
		status, err := rdr.ReadString('\n')
		status = strings.TrimSpace(status)
		if millis < 100 {
			expect2(t, "Expected status 200", "HTTP/1.0 200 OK", status)
			expect2(t, fmt.Sprintf("Expected no error for timeout %s", timeout), err, nil)
			resp := make([]byte, 1024)
			_, err := rdr.Read(resp)
			expect2(t, fmt.Sprintf("Expected no error for timeout %s", timeout), err, nil)
			responseStr := strings.TrimSpace(string(resp))
			idx := strings.Index(responseStr, helloWorld)
			//			log.Printf("::: %d\n", idx)
			msg := fmt.Sprintf("Expect response ending with [%s], received [%s]\n", helloWorld, responseStr)
			refute2(t, msg, idx, -1)
			log.Printf("Got response\n%s\n", responseStr)
		} else {
			msg := fmt.Sprintf("Expected error for timeout %d", millis)
			refute2(t, msg, err, nil)
			log.Printf("For %d, got error of type %s\n", millis, reflect.TypeOf(err))
			if err != io.EOF {
				oe := err.(*net.OpError)
				log.Printf("%s %s %s\n", oe.Err.Error(), oe.Op, oe.Net)
				expect2(t, msg, "read: connection reset by peer", oe.Err.Error())
			}
		}
	}
}

// This function tests that RestClient's timeout behavior works correctly.
func TestClientTimeout80(t *testing.T) {
	doTestTimeout(80, t)
}

func TestClientTimeout90(t *testing.T) {
	doTestTimeout(90, t)
}

func TestClientTimeoutHour(t *testing.T) {
	// Nobody is going to actually sleep for an hour, this is the test --
	// we are going to *try* to sleep for an hour, but it'll get interrupted.
	doTestTimeout(60*60*1000, t)
}

func doTestTimeout(timeout int, t *testing.T) {
	s := &http.Server{
		// Arbitrary post
		Addr:         ":0",
		Handler:      timeoutingHTTPServer{},
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
	}
	svcInfo, err := ListenAndServe(s)
	msg := <-svcInfo.Channel
	log.Println(msg)
	time.Sleep(time.Second)
	if err != nil {
		t.Error(err)
	}
	url := fmt.Sprintf("http://%s", svcInfo.Address)
	log.Printf("Listening on %s\n", url)
	client, err := NewRestClient(url, GetDefaultRestClientConfig())
	if err != nil {
		t.Error(err)
	}
	url = fmt.Sprintf("/?t=%dms", timeout)
	resp := make(map[string]string)
	start := time.Now()
	log.Printf("%v: Calling URL sleeping %d msec: %s\n", start, timeout, url)
	log.Printf("Time before: %v", start)
	err = client.Get(url, &resp)
	log.Printf("Time before: %v", start)
	log.Printf("Time after: %v", time.Now())
	log.Printf("Time elapsed in %v\n", time.Since(start))
	if err == nil {
		if resp["error"] != "" {
			t.Error(errors.New(resp["error"]))
		} else {
			// Less than a hundred millis -- see above -- we specified timeout on the
			// server side as 100 millis.
			if timeout < 100 {
				log.Printf("Ok for %d: %s\n", timeout, resp)
			} else {
				errMsg := fmt.Sprintf("Expected error, got %s", resp)
				log.Println(errMsg)
				t.Error(errors.New(errMsg))
			}
		}
	} else {
		log.Printf("Got error: %s (%s)\n", err.Error(), reflect.TypeOf(err))
		// Less than a hundred millis -- see above -- we specified timeout on the
		// server side as 100 millis.
		if timeout < 100 {
			t.Error(err)
		} else {
			log.Printf("Ok for %d: %s\n", timeout, resp)
		}

	}

	log.Println("OK!")
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
