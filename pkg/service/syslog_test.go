package service

import (
	"log"
	"net"
	"strings"
	"time"
)

func startServers() (*ECE, *strings.Builder, error) {
	output := &strings.Builder{}
	s := NewECE(500*time.Microsecond, "/dev/null", 0, 0, 0, false)
	s.logger = log.New(output, "", 0)
	s.Start("localhost:63514")

	return s, output, nil
}

func sendSyslog(structuredData string, messages []string) error {
	conn, err := net.Dial("tcp", "localhost:63514")
	if err != nil {
		return err
	}

	defer conn.Close()

	if structuredData != "" {
		structuredData = "[" + structuredData + "]"
	} else {
		structuredData = "-"
	}

	for _, msg := range messages {
		_, err = conn.Write([]byte(`<10>1 - - - - test ` + structuredData + ` ` + msg + "\n"))
		if err != nil {
			return err
		}
	}

	return nil
}

func within(d time.Duration, f func() (bool, string)) (bool, string) {
	err := ""
	ok := false

	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		ok, err = f()
		if ok { // 🔥
			return ok, err
		}
	}
	return ok, err
}
