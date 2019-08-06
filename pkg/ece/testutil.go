package ece

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/phayes/freeport"
	"github.com/pkg/errors"
	"log"
	"net"
	"sort"
	"strings"
	"time"
)

func testServer() (ece *ECE, logs *strings.Builder) {
	port, err := freeport.GetFreePort()
	if err != nil {
		log.Fatalf("Failed to get a free port on which to run the test server: %s", err)
	}

	address := fmt.Sprintf("127.0.0.1:%d", port)
	logs = &strings.Builder{}
	ece = NewECE(500*time.Microsecond, "/dev/null", 0, 0, 0, false, address)
	ece.logger = log.New(logs, "", 0)
	ece.Address = address
	ece.Debug = true
	err = ece.Start()
	if err != nil {
		log.Fatalf("Test Server failed to start: %s", err)
	}

	return ece, logs
}

func sendSyslog(structuredData string, messages []string, address string, tlsConfig *tls.Config) (err error) {
	fmt.Printf("Sending data to %s\n", address)

	var conn net.Conn

	if tlsConfig != nil {
		conn, err = tls.Dial("tcp", address, tlsConfig)
		if err != nil {
			err = errors.Wrap(err, "failed to dial tcp tls")
			return err
		}

		//state := conn.ConnectionState()
		//fmt.Printf("Connection: \n")
		//fmt.Printf("  Server Name: %s\n", state.ServerName)
		//fmt.Printf("  Handshake Finished: %v\n", state.HandshakeComplete)
		//fmt.Printf("  Resumed: %v\n", state.DidResume)

	} else {
		conn, err = net.Dial("tcp", address)
		if err != nil {
			err = errors.Wrap(err, "failed to dial tcp")
			return err
		}
	}

	if structuredData != "" {
		structuredData = "[" + structuredData + "]"
	} else {
		structuredData = "-"
	}

	for _, msg := range messages {
		fmt.Printf("Writing message ... ")
		num, err := conn.Write([]byte(`<10>1 - - - - test ` + structuredData + ` ` + msg + "\n"))
		if err != nil {
			err = errors.Wrapf(err, "failed to write to connection")
			return err
		}

		fmt.Printf("%d bytes written\n", num)
	}

	_ = conn.Close()

	return err
}

func within(d time.Duration, f func() (bool, string)) (bool, string) {
	err := ""
	ok := false

	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		ok, err = f()
		if ok {
			return ok, err
		}
	}
	return ok, err
}

func compareOutput(actual string, expected []OutputEvent) (bool, string) {
	expectedLines := []string{}
	for _, oe := range expected {
		ex, _ := json.Marshal(oe)
		expectedLines = append(expectedLines, string(ex))
	}

	actualLines := strings.Split(strings.TrimSpace(actual), "\n")
	sort.Strings(expectedLines)
	sort.Strings(actualLines)

	return strings.Join(expectedLines, "\n") == strings.Join(actualLines, "\n"), "exp:" + strings.Join(expectedLines, "\n") + "\n\n actual:" + strings.Join(actualLines, "\n")
}
