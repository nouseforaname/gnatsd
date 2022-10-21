// Copyright 2012-2018 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"crypto/rand"
	"crypto/tls"

	"crypto/x509"
	"encoding/pem"

	"github.com/nats-io/go-nats"
)

type serverInfo struct {
	Id           string `json:"server_id"`
	Host         string `json:"host"`
	Port         uint   `json:"port"`
	Version      string `json:"version"`
	AuthRequired bool   `json:"auth_required"`
	TLSRequired  bool   `json:"tls_required"`
	MaxPayload   int64  `json:"max_payload"`
}

func createClientAsync(ch chan *client, s *Server, cli net.Conn) {
	go func() {
		c := s.createClient(cli)
		// Must be here to suppress +OK
		c.opts.Verbose = false
		ch <- c
	}()
}

var defaultServerOptions = Options{
	Trace:  false,
	Debug:  false,
	NoLog:  true,
	NoSigs: true,
}

func rawSetup(serverOptions Options) (*Server, *client, *bufio.Reader, string) {
	cli, srv := net.Pipe()
	cr := bufio.NewReaderSize(cli, maxBufSize)
	s := New(&serverOptions)

	ch := make(chan *client)
	createClientAsync(ch, s, srv)

	l, _ := cr.ReadString('\n')

	// Grab client
	c := <-ch
	return s, c, cr, l
}

func setUpClientWithResponse() (*client, string) {
	_, c, _, l := rawSetup(defaultServerOptions)
	return c, l
}

func setupClient() (*Server, *client, *bufio.Reader) {
	s, c, cr, _ := rawSetup(defaultServerOptions)
	return s, c, cr
}

func checkClientsCount(t *testing.T, s *Server, expected int) {
	t.Helper()
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		if nc := s.NumClients(); nc != expected {
			return fmt.Errorf("The number of expected connections was %v, got %v", expected, nc)
		}
		return nil
	})
}

func TestClientCreateAndInfo(t *testing.T) {
	c, l := setUpClientWithResponse()

	if c.cid != 1 {
		t.Fatalf("Expected cid of 1 vs %d\n", c.cid)
	}
	if c.state != OP_START {
		t.Fatal("Expected state to be OP_START")
	}

	if !strings.HasPrefix(l, "INFO ") {
		t.Fatalf("INFO response incorrect: %s\n", l)
	}
	// Make sure payload is proper json
	var info serverInfo
	err := json.Unmarshal([]byte(l[5:]), &info)
	if err != nil {
		t.Fatalf("Could not parse INFO json: %v\n", err)
	}
	// Sanity checks
	if info.MaxPayload != MAX_PAYLOAD_SIZE ||
		info.AuthRequired || info.TLSRequired ||
		info.Port != DEFAULT_PORT {
		t.Fatalf("INFO inconsistent: %+v\n", info)
	}
}

func TestNonTLSConnectionState(t *testing.T) {
	_, c, _ := setupClient()
	state := c.GetTLSConnectionState()
	if state != nil {
		t.Error("GetTLSConnectionState() returned non-nil")
	}
}

func TestClientConnect(t *testing.T) {
	_, c, _ := setupClient()

	// Basic Connect setting flags
	connectOp := []byte("CONNECT {\"verbose\":true,\"pedantic\":true,\"tls_required\":false,\"echo\":false}\r\n")
	err := c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected state of OP_START vs %d\n", c.state)
	}
	if !reflect.DeepEqual(c.opts, clientOpts{Verbose: true, Pedantic: true, Echo: false}) {
		t.Fatalf("Did not parse connect options correctly: %+v\n", c.opts)
	}

	// Test that we can capture user/pass
	connectOp = []byte("CONNECT {\"user\":\"derek\",\"pass\":\"foo\"}\r\n")
	c.opts = defaultOpts
	err = c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected state of OP_START vs %d\n", c.state)
	}
	if !reflect.DeepEqual(c.opts, clientOpts{Echo: true, Verbose: true, Pedantic: true, Username: "derek", Password: "foo"}) {
		t.Fatalf("Did not parse connect options correctly: %+v\n", c.opts)
	}

	// Test that we can capture client name
	connectOp = []byte("CONNECT {\"user\":\"derek\",\"pass\":\"foo\",\"name\":\"router\"}\r\n")
	c.opts = defaultOpts
	err = c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected state of OP_START vs %d\n", c.state)
	}

	if !reflect.DeepEqual(c.opts, clientOpts{Echo: true, Verbose: true, Pedantic: true, Username: "derek", Password: "foo", Name: "router"}) {
		t.Fatalf("Did not parse connect options correctly: %+v\n", c.opts)
	}

	// Test that we correctly capture auth tokens
	connectOp = []byte("CONNECT {\"auth_token\":\"YZZ222\",\"name\":\"router\"}\r\n")
	c.opts = defaultOpts
	err = c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected state of OP_START vs %d\n", c.state)
	}

	if !reflect.DeepEqual(c.opts, clientOpts{Echo: true, Verbose: true, Pedantic: true, Authorization: "YZZ222", Name: "router"}) {
		t.Fatalf("Did not parse connect options correctly: %+v\n", c.opts)
	}
}

func TestClientConnectProto(t *testing.T) {
	_, c, r := setupClient()

	// Basic Connect setting flags, proto should be zero (original proto)
	connectOp := []byte("CONNECT {\"verbose\":true,\"pedantic\":true,\"tls_required\":false}\r\n")
	err := c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected state of OP_START vs %d\n", c.state)
	}
	if !reflect.DeepEqual(c.opts, clientOpts{Echo: true, Verbose: true, Pedantic: true, Protocol: ClientProtoZero}) {
		t.Fatalf("Did not parse connect options correctly: %+v\n", c.opts)
	}

	// ProtoInfo
	connectOp = []byte(fmt.Sprintf("CONNECT {\"verbose\":true,\"pedantic\":true,\"tls_required\":false,\"protocol\":%d}\r\n", ClientProtoInfo))
	err = c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected state of OP_START vs %d\n", c.state)
	}
	if !reflect.DeepEqual(c.opts, clientOpts{Echo: true, Verbose: true, Pedantic: true, Protocol: ClientProtoInfo}) {
		t.Fatalf("Did not parse connect options correctly: %+v\n", c.opts)
	}
	if c.opts.Protocol != ClientProtoInfo {
		t.Fatalf("Protocol should have been set to %v, but is set to %v", ClientProtoInfo, c.opts.Protocol)
	}

	// Illegal Option
	connectOp = []byte("CONNECT {\"protocol\":22}\r\n")
	wg := sync.WaitGroup{}
	wg.Add(1)
	// The client here is using a pipe, we need to be dequeuing
	// data otherwise the server would be blocked trying to send
	// the error back to it.
	go func() {
		defer wg.Done()
		for {
			if _, _, err := r.ReadLine(); err != nil {
				return
			}
		}
	}()
	err = c.parse(connectOp)
	if err == nil {
		t.Fatalf("Expected to receive an error\n")
	}
	if err != ErrBadClientProtocol {
		t.Fatalf("Expected err of %q, got  %q\n", ErrBadClientProtocol, err)
	}
	wg.Wait()
}

func TestClientPing(t *testing.T) {
	_, c, cr := setupClient()

	// PING
	pingOp := []byte("PING\r\n")
	go c.parse(pingOp)
	l, err := cr.ReadString('\n')
	if err != nil {
		t.Fatalf("Error receiving info from server: %v\n", err)
	}
	if !strings.HasPrefix(l, "PONG\r\n") {
		t.Fatalf("PONG response incorrect: %s\n", l)
	}
}

var msgPat = regexp.MustCompile(`\AMSG\s+([^\s]+)\s+([^\s]+)\s+(([^\s]+)[^\S\r\n]+)?(\d+)\r\n`)

const (
	SUB_INDEX   = 1
	SID_INDEX   = 2
	REPLY_INDEX = 4
	LEN_INDEX   = 5
)

func checkPayload(cr *bufio.Reader, expected []byte, t *testing.T) {
	// Read in payload
	d := make([]byte, len(expected))
	n, err := cr.Read(d)
	if err != nil {
		t.Fatalf("Error receiving msg payload from server: %v\n", err)
	}
	if n != len(expected) {
		t.Fatalf("Did not read correct amount of bytes: %d vs %d\n", n, len(expected))
	}
	if !bytes.Equal(d, expected) {
		t.Fatalf("Did not read correct payload:: <%s>\n", d)
	}
}

func TestClientSimplePubSub(t *testing.T) {
	_, c, cr := setupClient()
	// SUB/PUB
	go c.parse([]byte("SUB foo 1\r\nPUB foo 5\r\nhello\r\nPING\r\n"))
	l, err := cr.ReadString('\n')
	if err != nil {
		t.Fatalf("Error receiving msg from server: %v\n", err)
	}
	matches := msgPat.FindAllStringSubmatch(l, -1)[0]
	if len(matches) != 6 {
		t.Fatalf("Did not get correct # matches: %d vs %d\n", len(matches), 6)
	}
	if matches[SUB_INDEX] != "foo" {
		t.Fatalf("Did not get correct subject: '%s'\n", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'\n", matches[SID_INDEX])
	}
	if matches[LEN_INDEX] != "5" {
		t.Fatalf("Did not get correct msg length: '%s'\n", matches[LEN_INDEX])
	}
	checkPayload(cr, []byte("hello\r\n"), t)
}

func TestClientPubSubNoEcho(t *testing.T) {
	_, c, cr := setupClient()
	// Specify no echo
	connectOp := []byte("CONNECT {\"echo\":false}\r\n")
	err := c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	// SUB/PUB
	go c.parse([]byte("SUB foo 1\r\nPUB foo 5\r\nhello\r\nPING\r\n"))
	l, err := cr.ReadString('\n')
	if err != nil {
		t.Fatalf("Error receiving msg from server: %v\n", err)
	}
	// We should not receive anything but a PONG since we specified no echo.
	if !strings.HasPrefix(l, "PONG\r\n") {
		t.Fatalf("PONG response incorrect: %q\n", l)
	}
}

func TestClientSimplePubSubWithReply(t *testing.T) {
	_, c, cr := setupClient()

	// SUB/PUB
	go c.parse([]byte("SUB foo 1\r\nPUB foo bar 5\r\nhello\r\nPING\r\n"))
	l, err := cr.ReadString('\n')
	if err != nil {
		t.Fatalf("Error receiving msg from server: %v\n", err)
	}
	matches := msgPat.FindAllStringSubmatch(l, -1)[0]
	if len(matches) != 6 {
		t.Fatalf("Did not get correct # matches: %d vs %d\n", len(matches), 6)
	}
	if matches[SUB_INDEX] != "foo" {
		t.Fatalf("Did not get correct subject: '%s'\n", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'\n", matches[SID_INDEX])
	}
	if matches[REPLY_INDEX] != "bar" {
		t.Fatalf("Did not get correct reply subject: '%s'\n", matches[REPLY_INDEX])
	}
	if matches[LEN_INDEX] != "5" {
		t.Fatalf("Did not get correct msg length: '%s'\n", matches[LEN_INDEX])
	}
}

func TestClientNoBodyPubSubWithReply(t *testing.T) {
	_, c, cr := setupClient()

	// SUB/PUB
	go c.parse([]byte("SUB foo 1\r\nPUB foo bar 0\r\n\r\nPING\r\n"))
	l, err := cr.ReadString('\n')
	if err != nil {
		t.Fatalf("Error receiving msg from server: %v\n", err)
	}
	matches := msgPat.FindAllStringSubmatch(l, -1)[0]
	if len(matches) != 6 {
		t.Fatalf("Did not get correct # matches: %d vs %d\n", len(matches), 6)
	}
	if matches[SUB_INDEX] != "foo" {
		t.Fatalf("Did not get correct subject: '%s'\n", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'\n", matches[SID_INDEX])
	}
	if matches[REPLY_INDEX] != "bar" {
		t.Fatalf("Did not get correct reply subject: '%s'\n", matches[REPLY_INDEX])
	}
	if matches[LEN_INDEX] != "0" {
		t.Fatalf("Did not get correct msg length: '%s'\n", matches[LEN_INDEX])
	}
}

func (c *client) parseFlushAndClose(op []byte) {
	c.parse(op)
	for cp := range c.pcd {
		cp.mu.Lock()
		cp.flushOutbound()
		cp.mu.Unlock()
	}
	c.nc.Close()
}

func TestClientPubWithQueueSub(t *testing.T) {
	_, c, cr := setupClient()

	num := 100

	// Queue SUB/PUB
	subs := []byte("SUB foo g1 1\r\nSUB foo g1 2\r\n")
	pubs := []byte("PUB foo bar 5\r\nhello\r\n")
	op := []byte{}
	op = append(op, subs...)
	for i := 0; i < num; i++ {
		op = append(op, pubs...)
	}

	go c.parseFlushAndClose(op)

	var n1, n2, received int
	for ; ; received++ {
		l, err := cr.ReadString('\n')
		if err != nil {
			break
		}
		matches := msgPat.FindAllStringSubmatch(l, -1)[0]

		// Count which sub
		switch matches[SID_INDEX] {
		case "1":
			n1++
		case "2":
			n2++
		}
		checkPayload(cr, []byte("hello\r\n"), t)
	}
	if received != num {
		t.Fatalf("Received wrong # of msgs: %d vs %d\n", received, num)
	}
	// Threshold for randomness for now
	if n1 < 20 || n2 < 20 {
		t.Fatalf("Received wrong # of msgs per subscriber: %d - %d\n", n1, n2)
	}
}

func TestClientPubWithQueueSubNoEcho(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	nc1, err := nats.Connect(fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc1.Close()

	// Grab the client from server and set no echo by hand.
	s.mu.Lock()
	lc := len(s.clients)
	c := s.clients[s.gcid]
	s.mu.Unlock()

	if lc != 1 {
		t.Fatalf("Expected only 1 client but got %d\n", lc)
	}
	if c == nil {
		t.Fatal("Expected to retrieve client\n")
	}
	c.mu.Lock()
	c.echo = false
	c.mu.Unlock()

	// Queue sub on nc1.
	_, err = nc1.QueueSubscribe("foo", "bar", func(*nats.Msg) {})
	if err != nil {
		t.Fatalf("Error on subscribe: %v", err)
	}
	nc1.Flush()

	nc2, err := nats.Connect(fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc2.Close()

	n := int32(0)
	cb := func(m *nats.Msg) {
		atomic.AddInt32(&n, 1)
	}

	_, err = nc2.QueueSubscribe("foo", "bar", cb)
	if err != nil {
		t.Fatalf("Error on subscribe: %v", err)
	}
	nc2.Flush()

	// Now publish 100 messages on nc1 which does not allow echo.
	for i := 0; i < 100; i++ {
		nc1.Publish("foo", []byte("Hello"))
	}
	nc1.Flush()
	nc2.Flush()

	checkFor(t, 5*time.Second, 10*time.Millisecond, func() error {
		num := atomic.LoadInt32(&n)
		if num != int32(100) {
			return fmt.Errorf("Expected all the msgs to be received by nc2, got %d\n", num)
		}
		return nil
	})
}

func TestClientUnSub(t *testing.T) {
	_, c, cr := setupClient()

	num := 1

	// SUB/PUB
	subs := []byte("SUB foo 1\r\nSUB foo 2\r\n")
	unsub := []byte("UNSUB 1\r\n")
	pub := []byte("PUB foo bar 5\r\nhello\r\n")

	op := []byte{}
	op = append(op, subs...)
	op = append(op, unsub...)
	op = append(op, pub...)

	go c.parseFlushAndClose(op)

	var received int
	for ; ; received++ {
		l, err := cr.ReadString('\n')
		if err != nil {
			break
		}
		matches := msgPat.FindAllStringSubmatch(l, -1)[0]
		if matches[SID_INDEX] != "2" {
			t.Fatalf("Received msg on unsubscribed subscription!\n")
		}
		checkPayload(cr, []byte("hello\r\n"), t)
	}
	if received != num {
		t.Fatalf("Received wrong # of msgs: %d vs %d\n", received, num)
	}
}

func TestClientUnSubMax(t *testing.T) {
	_, c, cr := setupClient()

	num := 10
	exp := 5

	// SUB/PUB
	subs := []byte("SUB foo 1\r\n")
	unsub := []byte("UNSUB 1 5\r\n")
	pub := []byte("PUB foo bar 5\r\nhello\r\n")

	op := []byte{}
	op = append(op, subs...)
	op = append(op, unsub...)
	for i := 0; i < num; i++ {
		op = append(op, pub...)
	}

	go c.parseFlushAndClose(op)

	var received int
	for ; ; received++ {
		l, err := cr.ReadString('\n')
		if err != nil {
			break
		}
		matches := msgPat.FindAllStringSubmatch(l, -1)[0]
		if matches[SID_INDEX] != "1" {
			t.Fatalf("Received msg on unsubscribed subscription!\n")
		}
		checkPayload(cr, []byte("hello\r\n"), t)
	}
	if received != exp {
		t.Fatalf("Received wrong # of msgs: %d vs %d\n", received, exp)
	}
}

func TestClientAutoUnsubExactReceived(t *testing.T) {
	_, c, _ := setupClient()
	defer c.nc.Close()

	// SUB/PUB
	subs := []byte("SUB foo 1\r\n")
	unsub := []byte("UNSUB 1 1\r\n")
	pub := []byte("PUB foo bar 2\r\nok\r\n")

	op := []byte{}
	op = append(op, subs...)
	op = append(op, unsub...)
	op = append(op, pub...)

	ch := make(chan bool)
	go func() {
		c.parse(op)
		ch <- true
	}()

	// Wait for processing
	<-ch

	// We should not have any subscriptions in place here.
	if len(c.subs) != 0 {
		t.Fatalf("Wrong number of subscriptions: expected 0, got %d\n", len(c.subs))
	}
}

func TestClientUnsubAfterAutoUnsub(t *testing.T) {
	_, c, _ := setupClient()
	defer c.nc.Close()

	// SUB/UNSUB/UNSUB
	subs := []byte("SUB foo 1\r\n")
	asub := []byte("UNSUB 1 1\r\n")
	unsub := []byte("UNSUB 1\r\n")

	op := []byte{}
	op = append(op, subs...)
	op = append(op, asub...)
	op = append(op, unsub...)

	ch := make(chan bool)
	go func() {
		c.parse(op)
		ch <- true
	}()

	// Wait for processing
	<-ch

	// We should not have any subscriptions in place here.
	if len(c.subs) != 0 {
		t.Fatalf("Wrong number of subscriptions: expected 0, got %d\n", len(c.subs))
	}
}

func TestClientRemoveSubsOnDisconnect(t *testing.T) {
	s, c, _ := setupClient()
	subs := []byte("SUB foo 1\r\nSUB bar 2\r\n")

	ch := make(chan bool)
	go func() {
		c.parse(subs)
		ch <- true
	}()
	<-ch

	if s.sl.Count() != 2 {
		t.Fatalf("Should have 2 subscriptions, got %d\n", s.sl.Count())
	}
	c.closeConnection(ClientClosed)
	if s.sl.Count() != 0 {
		t.Fatalf("Should have no subscriptions after close, got %d\n", s.sl.Count())
	}
}

func TestClientDoesNotAddSubscriptionsWhenConnectionClosed(t *testing.T) {
	s, c, _ := setupClient()
	c.closeConnection(ClientClosed)
	subs := []byte("SUB foo 1\r\nSUB bar 2\r\n")

	ch := make(chan bool)
	go func() {
		c.parse(subs)
		ch <- true
	}()
	<-ch

	if s.sl.Count() != 0 {
		t.Fatalf("Should have no subscriptions after close, got %d\n", s.sl.Count())
	}
}

func TestClientMapRemoval(t *testing.T) {
	s, c, _ := setupClient()
	c.nc.Close()

	checkClientsCount(t, s, 0)
}

//TODO Potentially times out for unknown reasons [during merge, RP]
func TestAuthorizationTimeout(t *testing.T) {
	serverOptions := DefaultOptions()
	serverOptions.Authorization = "my_token"
	serverOptions.AuthTimeout = 0.4
	s := RunServer(serverOptions)
	defer s.Shutdown()

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", serverOptions.Host, serverOptions.Port))
	if err != nil {
		t.Fatalf("Error dialing server: %v\n", err)
	}
	defer conn.Close()
	client := bufio.NewReaderSize(conn, maxBufSize)
	if _, err := client.ReadString('\n'); err != nil {
		t.Fatalf("Error receiving info from server: %v\n", err)
	}
	time.Sleep(3 * secondsToDuration(serverOptions.AuthTimeout))
	l, err := client.ReadString('\n')
	if err != nil {
		t.Fatalf("Error receiving info from server: %v\n", err)
	}
	if !strings.Contains(l, "Authorization Timeout") {
		t.Fatalf("Authorization Timeout response incorrect: %q\n", l)
	}
}

// This is from bug report #18
func TestTwoTokenPubMatchSingleTokenSub(t *testing.T) {
	_, c, cr := setupClient()
	test := []byte("PUB foo.bar 5\r\nhello\r\nSUB foo 1\r\nPING\r\nPUB foo.bar 5\r\nhello\r\nPING\r\n")
	go c.parse(test)
	l, err := cr.ReadString('\n')
	if err != nil {
		t.Fatalf("Error receiving info from server: %v\n", err)
	}
	if !strings.HasPrefix(l, "PONG\r\n") {
		t.Fatalf("PONG response incorrect: %q\n", l)
	}
	// Expect just a pong, no match should exist here..
	l, _ = cr.ReadString('\n')
	if !strings.HasPrefix(l, "PONG\r\n") {
		t.Fatalf("PONG response was expected, got: %q\n", l)
	}
}

func TestUnsubRace(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	url := fmt.Sprintf("nats://%s:%d",
		s.getOpts().Host,
		s.Addr().(*net.TCPAddr).Port,
	)
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("Error creating client to %s: %v\n", url, err)
	}
	defer nc.Close()

	ncp, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("Error creating client: %v\n", err)
	}
	defer ncp.Close()

	sub, _ := nc.Subscribe("foo", func(m *nats.Msg) {
		// Just eat it..
	})
	nc.Flush()

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		for i := 0; i < 10000; i++ {
			ncp.Publish("foo", []byte("hello"))
		}
		wg.Done()
	}()

	time.Sleep(5 * time.Millisecond)

	sub.Unsubscribe()

	wg.Wait()
}

func TestTLSCloseClientConnection(t *testing.T) {
	opts, err := ProcessConfigFile("./configs/tls.conf")
	if err != nil {
		t.Fatalf("Error processing config file: %v", err)
	}
	opts.TLSTimeout = 100
	opts.NoLog = true
	opts.NoSigs = true
	s := RunServer(opts)
	defer s.Shutdown()

	endpoint := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	conn, err := net.DialTimeout("tcp", endpoint, 2*time.Second)
	if err != nil {
		t.Fatalf("Unexpected error on dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReaderSize(conn, 100)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("Unexpected error reading INFO: %v", err)
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("Unexpected error during handshake: %v", err)
	}
	br = bufio.NewReaderSize(tlsConn, 100)
	connectOp := []byte("CONNECT {\"user\":\"derek\",\"pass\":\"foo\",\"verbose\":false,\"pedantic\":false,\"tls_required\":true}\r\n")
	if _, err := tlsConn.Write(connectOp); err != nil {
		t.Fatalf("Unexpected error writing CONNECT: %v", err)
	}
	if _, err := tlsConn.Write([]byte("PING\r\n")); err != nil {
		t.Fatalf("Unexpected error writing PING: %v", err)
	}
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("Unexpected error reading PONG: %v", err)
	}

	// Check that client is registered.
	checkClientsCount(t, s, 1)
	var cli *client
	s.mu.Lock()
	for _, c := range s.clients {
		cli = c
		break
	}
	s.mu.Unlock()
	if cli == nil {
		t.Fatal("Did not register client on time")
	}
	// Test GetTLSConnectionState
	state := cli.GetTLSConnectionState()
	if state == nil {
		t.Error("GetTLSConnectionState() returned nil")
	}
	// Fill the buffer. Need to send 1 byte at a time so that we timeout here
	// the nc.Close() would block due to a write that can not complete.
	done := false
	for !done {
		cli.nc.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := cli.nc.Write([]byte("a")); err != nil {
			done = true
		}
		cli.nc.SetWriteDeadline(time.Time{})
	}
	ch := make(chan bool)
	go func() {
		select {
		case <-ch:
			return
		case <-time.After(6 * time.Second):
			fmt.Println("!!!! closeConnection is blocked, test will hang !!!")
			return
		}
	}()
	// Close the client
	cli.closeConnection(ClientClosed)
	ch <- true
}

func TestGetCertificateClientName(t *testing.T) {
	// common_name: client_id.client_name
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIEbDCCAtSgAwIBAgIRAO/BRBH6y/oSMamm2wa00D0wDQYJKoZIhvcNAQELBQAw
JjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQKEw1DbG91ZCBGb3VuZHJ5MB4XDTE4MDgz
MTE0MTYyMFoXDTQzMDgyNTE0MTYyMFowRjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQK
Ew1DbG91ZCBGb3VuZHJ5MR4wHAYDVQQDDBVjbGllbnRfaWQuY2xpZW50X25hbWUw
ggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCeGesCAbXAd8UQBv/1FZ4V
swoe1WbDiXz7cw4H0SpMR9u2f7mbmqKrlP5dpao3/RY2aDXRLhW+0aGE4IDpTLyO
+2Yl43xLfYJC2kEHyO0hCn4EuaOnSS1QWaGAO/F+gFUQQydFvYiycoA1MKIbDaVZ
lq9yNujEWvL9V6BSjyhLFbPlKf1Xrb3JpApKbiKFit3SP2gx3uCLiPdBQck1UPqd
zwsdPkAw1nZf1epjnuPxWQaWS2BtgBZRBD3E9s79B7XlxBBd9IFVxiEqFqV44hDH
LI6acIuLjExXoj1YejigrPhL1IIxy2RnywcI7ClK3jTQOZ3SctKu3fxigKAsojYl
AUHJ/vy9TxpruiP9OBCM5h0ekveh6jKSH4yqC6Cr1TJey8EKM9sJt3rUqT3+15ut
nPGIDpfjQ/zNxl9Y/LiBQUsecSGXsTU6BzPEiOGPOHutDgsKQh8MMgGygRsIxZaj
awjsltpOGxdSsslGfKWM9lrPzVHXHT263i2Fjd8vuUcCAwEAAaN1MHMwDgYDVR0P
AQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYD
VR0OBBYEFMSzXyER9N6Xvcr1KACEl1g8y16EMB8GA1UdIwQYMBaAFLxUWOCEfAw6
ilLLocIZAUaMGD7KMA0GCSqGSIb3DQEBCwUAA4IBgQBNht6oFdtUAzh5zfy8d9vG
UH28hs7wVQYurGjZxzBaGcItLnJ+3gh1Ybe/3bFE0LAtUG8VGY7T02XMBwdoyzi8
X3tLv6XY4SFUAcu90Xn5A3ViPKWoM4Qj0mAeUUU9+LInR2OLh834f90teOMhVH0t
wxq7fH3V6TA0L641csOdS6LK7smbdSIKb6FtEakBV9Num9QbddQXxOpzTm0+40Hb
30Ww+6eNeFgsppzs8ADeel6e4rypGytUXAHWM5AqQiP3fAdHzuMlcvZ7ps/IuKMy
oTKa9evvqTejk21jskWKtdkw3sMGxbwMObVyGu+Oicet+tso/3WQ/dgzWvvcEMXp
2ccHj6bi5yKZj5CmKjLK6BWTtZ28KNpIZR53mCt2eoBrxzYxPmHIgqvKlW9cZXY6
oDTz49prLWBnyzm94fcZqizIUYFXCyiKhzMq6/Ek7Srqs+goxsAL3OYzNeLaxGLL
fReqN2pxlQCkSeIXZm1xAsUehx+HmUI7xGZrTjop8Pk=
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	expectedCertificateClientName := "client_name"
	expectedCertificateClientID := "client_id"

	actualCertificateClientName, actualCertificateClientID, _ := client.GetCertificateClientNameAndID()

	if actualCertificateClientName != expectedCertificateClientName {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientName, expectedCertificateClientName)
	}

	if actualCertificateClientID != expectedCertificateClientID {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientID, expectedCertificateClientID)
	}
}

func TestGetCertificateClientNameNoCertificate(t *testing.T) {
	client := client{clientCertificate: nil}

	_, _, err := client.GetCertificateClientNameAndID()
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}

	expectedErrorMessage := "Client does not have a certificate"
	if err.Error() != expectedErrorMessage {
		stackFatalf(t, "Expected %s to equal %s", err.Error(), expectedErrorMessage)
	}
}

func TestGetCertificateClientNameNoCommonName(t *testing.T) {
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIETDCCArSgAwIBAgIRAJbzF9Tm/sPzNPx8TkrbH5MwDQYJKoZIhvcNAQELBQAw
JjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQKEw1DbG91ZCBGb3VuZHJ5MB4XDTE4MDgz
MTE0MTYyMVoXDTQzMDgyNTE0MTYyMVowJjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQK
Ew1DbG91ZCBGb3VuZHJ5MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA
0OtnJNvkof/ONDSLm2ADRy80/9RnVBGrFhLbfIRcONrkDYqC1b2WkDXQG9vcCpt9
CJgkv5KRFJybdosvUrLToK7zVxc/hcPWadaV/cpzainlslHpUzlx+vqshFgGPo3H
by550g+v3kSjdIsK3MQ+dzvmOnwSrOK0fdOScetQG8yHfkGiUGpTo/NLQA5Ad9Ac
iBR5jQwWmi9wut0GoXJCklZ9f5/zP9upe7J4IBdwq7qiUzqhzY0b92P+j8JVVb1B
L9fnA19rX7C/bysFiXOZgj/p2fLV2C/hoL2QUc7Lh4sEFaZYYBmSQDd665M5nDtV
GwIwolr1ASjsZLOcNNw0Q/eW4IknWgLh/HdwdHZqBtb2RhTqC2aIRl4euOTeQ6Bl
OwLaXnTCWCr21oKGVwYkTt8yxKHyKDGMB3V+vNZQa4CjkFApF+xGKE7TURcfl6Tn
UdifKKnrirGz7XH+9y/yv6uYpFm2SAQW/38dqla1zfcsYJXaBIXjOSGAoUGChpF/
AgMBAAGjdTBzMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDAjAM
BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBS5Am9nyXJ4ngOVotcMB15mtUy/NTAfBgNV
HSMEGDAWgBS8VFjghHwMOopSy6HCGQFGjBg+yjANBgkqhkiG9w0BAQsFAAOCAYEA
ZJvl1SAW78cPihxi8golNxhbvKYYIHBS1evVQmA1QgD4prrKLT3uRmd2RSXMiD//
i9GXtmmM1cd+Bpp3UxctfHRY+fUrRYkeUGwM+e4N85Xm6gu6YIWpoT15bPIA8bIX
g5NSrjVLdT5qn6TGlhhFXOLm8vhfMKpLoL0IfmptqXLbURAyXeTLie/U5qdUuhVA
z19xQzF1pJQVdYnvmA6LCXNK1i4lSP4b9r+KHUXFn2JrYcG/9TjAGXm6jtCwkiCS
EwFiywODVOFyd55pwPoWBBCHzxRuO7xtDIQq/AcFJH/96KfmUe2XogGFouq4m0Ih
iQcalQHWIngWEfXgmCSBpAIXy22AREc5SizTQ0MVawRF4BoHqNWooOPQEnLKUb5I
EIPzwMaAvuc7GJJ6PBtlQsr2kGkgUaOjCDU7WtqOr0eY5lb3XY+bAV0W1lTtpSYR
DDXiaU6yEDH2/Q76CZKyIfLU7c5iOZlLw9rfGmBgJSmc5syBVim9eFHD8sKZJvKT
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	expectedCertificateClientName := ""
	expectedCertificateClientID := ""

	actualCertificateClientName, actualCertificateClientID, _ := client.GetCertificateClientNameAndID()

	if actualCertificateClientName != expectedCertificateClientName {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientName, expectedCertificateClientName)
	}

	if actualCertificateClientID != expectedCertificateClientID {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientID, expectedCertificateClientID)
	}
}

func TestGetCertificateClientNameCommonNameNoDots(t *testing.T) {
	// common_name: client_name
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIEYTCCAsmgAwIBAgIQV1qMCHeFUMbn+bmvx8LULjANBgkqhkiG9w0BAQsFADAm
MQwwCgYDVQQGEwNVU0ExFjAUBgNVBAoTDUNsb3VkIEZvdW5kcnkwHhcNMTgwODMx
MTQxNjIyWhcNNDMwODI1MTQxNjIyWjA8MQwwCgYDVQQGEwNVU0ExFjAUBgNVBAoT
DUNsb3VkIEZvdW5kcnkxFDASBgNVBAMMC2NsaWVudF9uYW1lMIIBojANBgkqhkiG
9w0BAQEFAAOCAY8AMIIBigKCAYEAylfC99bvC84emQL4m97kxtBFyU67gUBdFZyF
uU5hjOedWMeawUfSDti6KXQZl0lxg3+sb8hL6pNyEgiYyw+rRmgn8LkhSEqGDdNC
gggQ6rQzk6MXr/bsA+Knisb6YBdwg7YQ/kKrn+l9fgauUf4CPrq6PL6NgQFr92sw
yytG4mM2EnU7PwhWl67K5IpQFdcw9vMv13XwpDMHBoi6vkxwAEHOOJ9AxQJ5Q3av
2jIsWR13bFfATrlyRSUiIhT0H2WrgIQY0CPT8ON5X3YoVZpfThbIjCGPf7r1kJiU
wDOfDRWvdGFntUIefjco6xdvq/KRXlc5LJ7oNIhBpR1wKcxlY5ZknGqMWa9Du5hS
0Xxv37STp/4Ab4wO/YeImQ9DCLhHgtwz07PHx6QLlM/TyOO4kKIEi6wGrEmIfBJz
EOurQsoF9E3dzHNfI/pAybvQXVA8zbeZ0AcBWXEQo7eLIzhk7xkKDkq5otsyY3zy
ZaqojSYWUvLRbdWVAsRM0Ep3oyMlAgMBAAGjdTBzMA4GA1UdDwEB/wQEAwIFoDAT
BgNVHSUEDDAKBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQtXnKS
9+WGaJruyG4MlYSb69po+DAfBgNVHSMEGDAWgBS8VFjghHwMOopSy6HCGQFGjBg+
yjANBgkqhkiG9w0BAQsFAAOCAYEAF1ZykxFryem0/y5D5nIa0ReQF2NYKZTs7H3G
NHSA6qjZFzQQ4/XNAJy6FptXjViUiV5LjniVlm1LF50dCOYLL2jP2vr7VPTWSX/e
Ul53yVXRp69nV1rcTaRErfRZMyHmKYxsaNVPsNIyq4E7nPMCugYli7uZnvsUrH9l
KG/1F32zIsGoaVeNU0QanBgqusHoS1gJpvjh02rNU30Fr32EE3hxBYRjC/eYia04
iqrYveo2hiTU85FB2AKYS1QZzG8wwYLU/QDVqD72DSOnRINh8+67BeESu5X+D2v7
1QhmeAQxAwPnK4ZOP4rRHS4ckswGLtT2UX/1pcXpYHTpMpTDqh4HaN7BDIYa5S8a
spE4g7uhnQUfiJxnylCvyLh4FAKEep2F5DhhVVDzR8GGoxPLK2I8pFLMdHgPR3Y7
QEfAianw8jUT4LrbUaXm8VLhGYbyc7GnbH5Chw8A6Q12ZqxBqIO6jFsecgT/vmbg
LL+vMi1zsY4yQfuXS5KNQ1YoyVaC
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	_, _, err := client.GetCertificateClientNameAndID()

	if err == nil {
		t.Fatalf("Expected error but none received.")
	}

	expectedErrorMessage := "Clients must present both NAME and ID. `<client_id>.<client_name>`"
	if err.Error() != expectedErrorMessage {
		stackFatalf(t, "Expected %s to equal %s", err.Error(), expectedErrorMessage)
	}
}

func TestGetCertificateClientNameCommonNameOneDot(t *testing.T) {
	// common_name : .client_name
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIEYjCCAsqgAwIBAgIQVt9ql1mSc6QRmwr6dFJ9UTANBgkqhkiG9w0BAQsFADAm
MQwwCgYDVQQGEwNVU0ExFjAUBgNVBAoTDUNsb3VkIEZvdW5kcnkwHhcNMTgwODMx
MTQxNjIyWhcNNDMwODI1MTQxNjIyWjA9MQwwCgYDVQQGEwNVU0ExFjAUBgNVBAoT
DUNsb3VkIEZvdW5kcnkxFTATBgNVBAMMDC5jbGllbnRfbmFtZTCCAaIwDQYJKoZI
hvcNAQEBBQADggGPADCCAYoCggGBAOs0tNToV+EmJrtxFnfLox+o6GzgfaT39Om1
Y3HtImylam3mUEBo9oOT28uDp1MYQCSxl3deOYcm3kV5W+Mxvybm75d4wxNpT7NY
QXFr8nIYX4CCt1CqFsKG2uog/qbR6KhJycKqIFfXiMygEsRUSI33gceVuUkegkyq
CXvgn04VVyc06HkhveQPAGONDTP0uhEsaM7fAHbdA/cADpqfImajPnPE8D84brPy
i+Kk+SrG2MlmbM94h6YSVJOsdTGeCF3Z3fj5x2YZWRm46Duk4+ZJD7b1VOin36RE
FAN2rW34wZxRkIwPSpnGAbu9Odbaq+J5C3lVBjK2evCsam9sKfT+Lltfp/05W7UK
eCfD5m/gDJkP/Xs6JzSgjEqvoduThI/vBIlgP9yPQ31FmABTRJZ8Hvy53SvfONfB
GMoJi/kQpoTICyk2eQxLQWDU3/A5pur2840EjPB6uI5O/0/g0C99NdjdO9lU9sOd
bN83f3KIZoCtAYs/LPO8mCYb74IIHQIDAQABo3UwczAOBgNVHQ8BAf8EBAMCBaAw
EwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU51Bx
Gtg5rSyoPoPcWM3p7pGFF0YwHwYDVR0jBBgwFoAUvFRY4IR8DDqKUsuhwhkBRowY
PsowDQYJKoZIhvcNAQELBQADggGBAFmY0czAyNRKMp1/yEFrgLaXjXQ/M9bSuO77
9iNFn+tKgxQfuNYVTj50DajRtwvljQjufP2tflt6FAZ6G0gvyY/BajJeL16GefqG
02Hs8xjz2GBuUHgnDC345i8PObIeuagXnt49aayyL/NlZvxeVWrTe5ZgzfiiJ/2u
D9zupIOSq18BZMSjSZg3nC2yB6B/1LeazCZtfWfXY3tcRmL2+Q+S2Ub2cptjZuM8
TA+u25t6nKasaPOXTTbjdhIiM17y5t57FBNR0t3dgkg6CX1FAC5EVcNBy3gfpBip
v0H3pjB8w15BKt2u49OmHExRSOI7Lq4dqfZaR+r/v8518HFsE6FcdjmF27dAopR4
H/NDi3CqX1Av+iyHwUELbIu3BQNoba+jKW2VzvvUNRsb12YHJwW9ybSeK9qv+OL8
lqBtX+txTkAALzHwTg8Bdh/09s6MAos27fki+0TISXNQthjd2+o9WL9sEByIP9XD
lNZ9C2dpw+Tn5lz9+K0Vb7nEquhjwg==
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	expectedCertificateClientName := "client_name"
	expectedCertificateClientID := ""

	actualCertificateClientName, actualCertificateClientID, _ := client.GetCertificateClientNameAndID()

	if actualCertificateClientName != expectedCertificateClientName {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientName, expectedCertificateClientName)
	}

	if actualCertificateClientID != expectedCertificateClientID {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientID, expectedCertificateClientID)
	}
}

func TestGetCertificateClientNameCommonNameMultiDots(t *testing.T) {
	// common_name : client_id.client_name_part1.client_name_part2
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIEgzCCAuugAwIBAgIQXJ+LkV475EuNMzT9kiI17TANBgkqhkiG9w0BAQsFADAm
MQwwCgYDVQQGEwNVU0ExFjAUBgNVBAoTDUNsb3VkIEZvdW5kcnkwHhcNMTgwODMx
MTQxNjIyWhcNNDMwODI1MTQxNjIyWjBeMQwwCgYDVQQGEwNVU0ExFjAUBgNVBAoT
DUNsb3VkIEZvdW5kcnkxNjA0BgNVBAMMLWNsaWVudF9pZC5jbGllbnRfbmFtZV9w
YXJ0MS5jbGllbnRfbmFtZV9wYXJ0MjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
AYoCggGBALkc81ycMshLj8UBGzq+RLN7cnWHLyYNI9X7zaHDCuMaTYVrA/4X7dHl
GvnAny198TUffCXHqEgCQ7qzwKnsMi6GWYtrTWFiyFsGoK/u/Lt9DRlAgaKy+NCk
z4doyQHL5tBxq/oHlFTMwDmlJ81HgW5c9Vy5+qE5nJj/CppGMIli8aJuZ0u/OK6u
2YQzz99fXaoQ7ebZPuh7x8BdKTWexEQpUqPXCLyYKZY1qrmN8biJKmYBu8tJ/ukJ
v9d5ApDpW7XhTni7veIvN2I+8NETrgTmMXIh9S7x/yyKbbX95DMTd5UYF8uCrg2z
hKiFJ8pSnGr96pq7wvork+v/Y9aNE9Ov6fdLkRXDly3AJ3H3k46hoNWuHsySbG51
BG39dmdGzgCa2vLIRqwqX9VruL0GG2LQTAv1kss1yZwLJk/8NYgxrZ7Bbv/iYRpV
S6lfYxQrNNaW/J6p9e2b7Kx31wy6i2CzktYX3c/HB0nOZ+RZ8W3aRtvMpuiXDhtG
RjsvbYicwQIDAQABo3UwczAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUkv0zsSXXtXa+vzx0nuu/jR/3
NwswHwYDVR0jBBgwFoAUvFRY4IR8DDqKUsuhwhkBRowYPsowDQYJKoZIhvcNAQEL
BQADggGBAEAZaJo55BL0cvOro93iq3WMwvSQDkfMFYP/KctFMua2dQNBC/FntCqT
nQnZO+UtS860L4jcuz+VDzx4xhXWxIF9CJyZ1/jk+lCBpC7VFVqZvD7UXmzYvlre
yCiwwY0yDRCcdCLqLlHxFCNy8lfALngfiORiUf8p0CojP5eK5CFZWNolQDdN+qb4
5jSvuNxQX6PfNmpwoiQ/NeRHOjyuByGJxZ6heFfh/FWtleT+k/mf8RWNgojMzla6
/GKWOa2JHRduGLY0eWhHt+dpulvMwgevlLkRkNF3l6pflm2XSGjtjlZBcRIn1/WE
LuEjlBYhAJ1tmbazS1EDdH3+hmpElRcYSkp07SbqU3MFG/UU4BZ7iRZA4WdJTvTo
glpcvxRbwR013A/LNz9D0tyEBZWLm1bPTzIyMgb85FS5f4AxCE56kMycvNv5Yvcb
WQussdQhSFfRLjzhVHqHwaPKNnzzVfFW3ZYN57QtSi5VhHZ9duBrdRWdSqw42YkW
st5jba9fkw==
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	expectedCertificateClientName := "client_name_part1.client_name_part2"
	expectedCertificateClientID := "client_id"

	actualCertificateClientName, actualCertificateClientID, _ := client.GetCertificateClientNameAndID()

	if actualCertificateClientName != expectedCertificateClientName {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientName, expectedCertificateClientName)
	}

	if actualCertificateClientID != expectedCertificateClientID {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientID, expectedCertificateClientID)
	}
}

func TestGetCertificateClientNameCommonNameMultiConsecutiveDots(t *testing.T) {
	// common_name : ..client_name
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIEZDCCAsygAwIBAgIRAMeuhkKEWL9mkRC+ILqG3a8wDQYJKoZIhvcNAQELBQAw
JjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQKEw1DbG91ZCBGb3VuZHJ5MB4XDTE4MDgz
MTE0MTYyM1oXDTQzMDgyNTE0MTYyM1owPjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQK
Ew1DbG91ZCBGb3VuZHJ5MRYwFAYDVQQDDA0uLmNsaWVudF9uYW1lMIIBojANBgkq
hkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAuitnz30662A6QQkxqGtPmvV/KfaR3DRb
KGqdDI3+V/BExruai1ydl7s/XbVRJuTPTBR2fVbGK3+HgOu2fI0xD/0qUa3zlRnr
okJY1ik0S/6uhw9tKYGHmrXjz44hw1T7UhMd7qfdCwZDgEydpHBjp1BMipEtdb6u
wcROO6yVW0sn90ALuB63NzFVJB26qlxcW3+ql/iSRziXRGYhLnSnf+n2TYaEitOm
Hs2HlwMie1zB9I5ObQCsEwjzcq5hxtmWsMrzuOxl+3jn4mV2vaOrAww9LJbyWzN5
5o8L3CnPTQCdEOTCAjKdcyBb2DIVTLAHN3S5GUeUSgMuYlh7ExEgQUz8dFqNQk0l
uZAM+xzM9LNGJNlSZmD4yRVUYETjDrv3/93PTIHRXX0HnIcXczV7CnWoyNfttUxU
Gou0xUcPU6HFWzIHdUe7jYhXkxkNTBcoJMwL2+8WuY+HxfS34O8NzBNLCNFQpFeu
LitKOWDgwmb6jaoes+AiUHzBEvp5g7MnAgMBAAGjdTBzMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRX
FSd1S7cey7QiX1VRhI+9+osZnzAfBgNVHSMEGDAWgBS8VFjghHwMOopSy6HCGQFG
jBg+yjANBgkqhkiG9w0BAQsFAAOCAYEAG7W6IobBxRFVDXHsvfM28utD7GYRiwTx
EJlqYq6xjESmjMwBi6CrYN9CyD27DZvDhcxTROtJbBGJKd2yzrQmU6AJ2sTG4yvX
mMMCwDUDjHTbOh7f24cWm5fTbNzNCHm/5znaRgxZN3DQnomQBJwpUSRDSlC5I71Z
vTZyF+smeEYULEQC3a2CTeGFC3jT7uD34GcK5kQQeRCIoYonao8wtPifQ/O8b1gX
TnlQnOltvguzttKxud/d/h3Pch5DTV6rlv2s5QoiaUS+0BU9wOlanzBm2ztZSHSM
46cPXwvhEdggtClBciWDodRUpwdkAHw9X0Iz/g51V6QTz+P/Kl8ou3IAhECUkiiv
GipeD4MLpX9xEUZxFmN1oq9XXp7tEcBcd/QRYuyyz1uVXUwGncNTvNiT0keao15p
ot8cDwFJWqb7zRkbobmfGe4XhF+b3jl7h0a2tcioKyIU6y9bxags1Bo4KNAAK6kW
8B7cE2rYe7gDNLT+qTU2DwPePvKyZqFY
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	expectedCertificateClientName := ".client_name"
	expectedCertificateClientID := ""

	actualCertificateClientName, actualCertificateClientID, _ := client.GetCertificateClientNameAndID()

	if actualCertificateClientName != expectedCertificateClientName {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientName, expectedCertificateClientName)
	}

	if actualCertificateClientID != expectedCertificateClientID {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientID, expectedCertificateClientID)
	}
}

func TestGetCertificateClientNameCommonNameStarWildcard(t *testing.T) {
	// common_name: *.client_1
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIEfjCCAuagAwIBAgIQcAScsbNUn8uVB+ekMFDu1zANBgkqhkiG9w0BAQsFADAm
MQwwCgYDVQQGEwNVU0ExFjAUBgNVBAoTDUNsb3VkIEZvdW5kcnkwHhcNMTgwODMx
MTM0NzI1WhcNNDMwODI1MTM0NzI1WjA7MQwwCgYDVQQGEwNVU0ExFjAUBgNVBAoT
DUNsb3VkIEZvdW5kcnkxEzARBgNVBAMMCiouY2xpZW50XzEwggGiMA0GCSqGSIb3
DQEBAQUAA4IBjwAwggGKAoIBgQDOz1BHItXDNAMLia4I4mhpkAAVEyI0DWUBNsZ4
DTt43J6fNPznlydPcv7eH42G91SU1ff+lWiTfaPQbhhDeoXbSTD5CQe1oe5ekHPo
TZuO/4b2EpghLjojrtu1E6VSxMKbG6bPDBv9ONUoH7B6jIGfPQuaFDuGHXwB6I77
2F2gHcP5Riefqz1PTQC5ErlPhX9SwSBzkTzoH3RQugx4Yj9cH9h0+U0Q5liZqG4h
3V9L+b9d2m+XZnJcY9LI5pEOkfC9JYk+7GhURGW+HzrTpR/zPtU70rCjsZrJwSav
S6UACV/dIC4UYKdY4y79jgzkd35PlXrKz/zgerfm8i5+vP609Zk+/xSm1Irdzog+
DeJZ0EIDwYFADbqERi3DR/LddD3wLjAG2HKFhrULF4qBvwo1W50szHsaxY3U19Fx
+KkKndRom41j/+LVsqjuQc7g8V4KQ/XJMZIqMai18LBMoMsg3DcVra7G73ju8vh/
A0Bx3hIYiIuj1vwQsM8bzEArUnECAwEAAaOBkjCBjzAOBgNVHQ8BAf8EBAMCBaAw
EwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUz+V3
RhgQ15J/B8jJt9Ib5j90rK0wHwYDVR0jBBgwFoAUvFRY4IR8DDqKUsuhwhkBRowY
PsowGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMA0GCSqGSIb3DQEBCwUAA4IB
gQCp5NvZbKlGgFhrWWyQiaxSaoImR0q1sqOtl9KIFysvfjuTbOOEaGcVD5qBG8jk
E+EA0tZN0zi7DpeZUTB7Mdeejd8rG8Zunu24xWDQl7hvSN7KngMzprFWOWQdFOuI
1bnLRemQirsxiHH57R4fSyNbeksGfhRvKoplpT2/UW5GrzR9sRw50/xk2lQR+RZF
oZcVZqCQB2IpdsmdH6rqAGOb2IzOe7nEAtmdM8wkyCPkWty2jxoU3yhacH/hkehp
RNt6g6t260VB3j5n3Y2ZcHSjq0A22aH4+RqfwyI2lon8aIbz+gdhI6heuaaGEupB
ojhjB3kBaEcehRCrVPUNY5WcXcmOx+XJ/JK2RTSMF0pZ/h6I3r1iKoimxUfBNlGw
YP+QHLvEWpdY4N/kQpoub1nnHdqpQnqUoc5P6YreaafT1QSBg3a2hkrxm7SEaFip
xzrq3/iJDqkBIers88aIoF2HKDEu7GQXYp7DCt/SeNCK1BeHAYyBRHlJhB1VmZpL
fuQ=
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	_, _, err := client.GetCertificateClientNameAndID()

	if err == nil {
		t.Fatalf("Expected error but none received.")
	}

	expectedErrorMessage := "Client ID cannot contain * or >"
	if err.Error() != expectedErrorMessage {
		stackFatalf(t, "Expected %s to equal %s", err.Error(), expectedErrorMessage)
	}
}

func TestGetCertificateClientNameCommonNameStarGreater(t *testing.T) {
	// common_name: >.client_1
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIEfzCCAuegAwIBAgIRAOPxuAtBD+iaC730BlvvXScwDQYJKoZIhvcNAQELBQAw
JjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQKEw1DbG91ZCBGb3VuZHJ5MB4XDTE4MDgz
MTEzNDcyNVoXDTQzMDgyNTEzNDcyNVowOzEMMAoGA1UEBhMDVVNBMRYwFAYDVQQK
Ew1DbG91ZCBGb3VuZHJ5MRMwEQYDVQQDDAo+LmNsaWVudF8xMIIBojANBgkqhkiG
9w0BAQEFAAOCAY8AMIIBigKCAYEAqvDd1wR/77JQL3nQFsEP9GHxmK2Cx45LXrAt
KiGs88EdYjn9Dk0YefB1b0OZ/VrOGs0+IxTQRjdfmW3BRzBd7HiATbncuUeF68MG
Uq32O7f1qjuCSHaLEi1TEo+NCHLuFiztCjE9UqmPtBnAMRpbIYdQWUYtk8NN/Zdx
qLX1803DUW42LGBOBHYVADbkCqFj97lZsObybdqMeCT0bVmpSSibJrERFzpE11dI
4pPedSiJAF948QynE4Paj8LQ76CxwNdE/B2jeJmox8lJwlSGNIIcib/JquN+C09N
h3KfXcdlf1BujTLK38yPoBBxCXotrzkOsKAb37B5CSx/LlkugNsutU1fsk7mt+xh
1DIIZKoovRSMm2x3q3MwCHw3PArVzDjnZgyyCwK4sXMpVJ3zP1Wx6knj/QTqcWA7
41awP5P+dIwy2+O1Qzug65j+9zSgHG34n4ZRkcZMcGOQ6Yoyp5UB95n7vnOQQ+yl
DYeWjFFhZEuuOsz6an3Yr/N7a3GbAgMBAAGjgZIwgY8wDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBeT
cLl+fiL5uUEICvtbVBD76sE2MB8GA1UdIwQYMBaAFLxUWOCEfAw6ilLLocIZAUaM
GD7KMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOC
AYEAAtFBh7p9ol0YifdAWm9wrhUeOnpiQf5FRrlmi6menkIxW9ICRmqgudxDV1oS
yO8mJDadOX+3FBtiYQlaLb1HV4odSDQZjN3oLlM0L/XIlH16iiJvpvaMMVzUNqmo
gZH2cHgDW03OB5ZzJfZEbKVzfyDnhrq3Hx/s8muBUwUmrWGUtilbj0VnfnasQkJ3
tH6r8pcGR9yarEqhw5VqAZbgbTdDrrYsOteKpwky1xsRlVqTp6uaevYIKx+sB8r3
y57CHkhCMY5zQMY27M98bH3XXZ8yZjHQlOeWo6MTMJPobFucCvvep26JtB2pav9I
VAcRK9aBl4/KCad2iB8KijWX8K4CgqkRok6rWD6SEFUHgmZYD7CqcTu1y/k9lH0v
lZBFsQc986O/cajwj0IEHRCiuZvEYH8jRT+SgVFrxLUfukkHJk+CG2uQowBzYoeD
Jh3bsBTtW0H5iOasmicFtkZ/bG1ADqVgNJZV3C1MbmxOxJ+ofN+K5p2geS6pzLQK
aH3T
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	_, _, err := client.GetCertificateClientNameAndID()

	if err == nil {
		t.Fatalf("Expected error but none received.")
	}

	expectedErrorMessage := "Client ID cannot contain * or >"
	if err.Error() != expectedErrorMessage {
		stackFatalf(t, "Expected %s to equal %s", err.Error(), expectedErrorMessage)
	}
}

// This tests issue #558
func TestWildcardCharsInLiteralSubjectWorks(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	nc, err := nats.Connect(fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc.Close()

	ch := make(chan bool, 1)
	// This subject is a literal even though it contains `*` and `>`,
	// they are not treated as wildcards.
	subj := "foo.bar,*,>,baz"
	cb := func(_ *nats.Msg) {
		ch <- true
	}
	for i := 0; i < 2; i++ {
		sub, err := nc.Subscribe(subj, cb)
		if err != nil {
			t.Fatalf("Error on subscribe: %v", err)
		}
		if err := nc.Flush(); err != nil {
			t.Fatalf("Error on flush: %v", err)
		}
		if err := nc.LastError(); err != nil {
			t.Fatalf("Server reported error: %v", err)
		}
		if err := nc.Publish(subj, []byte("msg")); err != nil {
			t.Fatalf("Error on publish: %v", err)
		}
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("Should have received the message")
		}
		if err := sub.Unsubscribe(); err != nil {
			t.Fatalf("Error on unsubscribe: %v", err)
		}
	}
}

func TestDynamicBuffers(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	nc, err := nats.Connect(fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc.Close()

	// Grab the client from server.
	s.mu.Lock()
	lc := len(s.clients)
	c := s.clients[s.gcid]
	s.mu.Unlock()

	if lc != 1 {
		t.Fatalf("Expected only 1 client but got %d\n", lc)
	}
	if c == nil {
		t.Fatal("Expected to retrieve client\n")
	}

	// Create some helper functions and data structures.
	done := make(chan bool)          // Used to stop recording.
	type maxv struct{ rsz, wsz int } // Used to hold max values.
	results := make(chan maxv)

	// stopRecording stops the recording ticker and releases go routine.
	stopRecording := func() maxv {
		done <- true
		return <-results
	}
	// max just grabs max values.
	max := func(a, b int) int {
		if a > b {
			return a
		}
		return b
	}
	// Returns current value of the buffer sizes.
	getBufferSizes := func() (int, int) {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.in.rsz, c.out.sz
	}
	// Record the max values seen.
	recordMaxBufferSizes := func() {
		ticker := time.NewTicker(10 * time.Microsecond)
		defer ticker.Stop()

		var m maxv

		recordMax := func() {
			rsz, wsz := getBufferSizes()
			m.rsz = max(m.rsz, rsz)
			m.wsz = max(m.wsz, wsz)
		}

		for {
			select {
			case <-done:
				recordMax()
				results <- m
				return
			case <-ticker.C:
				recordMax()
			}
		}
	}
	// Check that the current value is what we expected.
	checkBuffers := func(ers, ews int) {
		t.Helper()
		rsz, wsz := getBufferSizes()
		if rsz != ers {
			t.Fatalf("Expected read buffer of %d, but got %d\n", ers, rsz)
		}
		if wsz != ews {
			t.Fatalf("Expected write buffer of %d, but got %d\n", ews, wsz)
		}
	}

	// Check that the max was as expected.
	checkResults := func(m maxv, rsz, wsz int) {
		t.Helper()
		if rsz != m.rsz {
			t.Fatalf("Expected read buffer of %d, but got %d\n", rsz, m.rsz)
		}
		if wsz != m.wsz {
			t.Fatalf("Expected write buffer of %d, but got %d\n", wsz, m.wsz)
		}
	}

	// Here is where testing begins..

	// Should be at or below the startBufSize for both.
	rsz, wsz := getBufferSizes()
	if rsz > startBufSize {
		t.Fatalf("Expected read buffer of <= %d, but got %d\n", startBufSize, rsz)
	}
	if wsz > startBufSize {
		t.Fatalf("Expected write buffer of <= %d, but got %d\n", startBufSize, wsz)
	}

	// Send some data.
	data := make([]byte, 2048)
	rand.Read(data)

	go recordMaxBufferSizes()
	for i := 0; i < 200; i++ {
		nc.Publish("foo", data)
	}
	nc.Flush()
	m := stopRecording()

	if m.rsz != maxBufSize && m.rsz != maxBufSize/2 {
		t.Fatalf("Expected read buffer of %d or %d, but got %d\n", maxBufSize, maxBufSize/2, m.rsz)
	}
	if m.wsz > startBufSize {
		t.Fatalf("Expected write buffer of <= %d, but got %d\n", startBufSize, m.wsz)
	}

	// Create Subscription to test outbound buffer from server.
	nc.Subscribe("foo", func(m *nats.Msg) {
		// Just eat it..
	})
	go recordMaxBufferSizes()

	for i := 0; i < 200; i++ {
		nc.Publish("foo", data)
	}
	nc.Flush()

	m = stopRecording()
	checkResults(m, maxBufSize, maxBufSize)

	// Now test that we shrink correctly.

	// Should go to minimum for both..
	for i := 0; i < 20; i++ {
		nc.Flush()
	}
	checkBuffers(minBufSize, minBufSize)
}

// Similar to the routed version. Make sure we receive all of the
// messages with auto-unsubscribe enabled.
func TestQueueAutoUnsubscribe(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	nc, err := nats.Connect(fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc.Close()

	rbar := int32(0)
	barCb := func(m *nats.Msg) {
		atomic.AddInt32(&rbar, 1)
	}
	rbaz := int32(0)
	bazCb := func(m *nats.Msg) {
		atomic.AddInt32(&rbaz, 1)
	}

	// Create 1000 subscriptions with auto-unsubscribe of 1.
	// Do two groups, one bar and one baz.
	for i := 0; i < 1000; i++ {
		qsub, err := nc.QueueSubscribe("foo", "bar", barCb)
		if err != nil {
			t.Fatalf("Error on subscribe: %v", err)
		}
		if err := qsub.AutoUnsubscribe(1); err != nil {
			t.Fatalf("Error on auto-unsubscribe: %v", err)
		}
		qsub, err = nc.QueueSubscribe("foo", "baz", bazCb)
		if err != nil {
			t.Fatalf("Error on subscribe: %v", err)
		}
		if err := qsub.AutoUnsubscribe(1); err != nil {
			t.Fatalf("Error on auto-unsubscribe: %v", err)
		}
	}
	nc.Flush()

	expected := int32(1000)
	for i := int32(0); i < expected; i++ {
		nc.Publish("foo", []byte("Don't Drop Me!"))
	}
	nc.Flush()

	checkFor(t, 5*time.Second, 10*time.Millisecond, func() error {
		nbar := atomic.LoadInt32(&rbar)
		nbaz := atomic.LoadInt32(&rbaz)
		if nbar == expected && nbaz == expected {
			return nil
		}
		return fmt.Errorf("Did not receive all %d queue messages, received %d for 'bar' and %d for 'baz'",
			expected, atomic.LoadInt32(&rbar), atomic.LoadInt32(&rbaz))
	})
}
