package ece

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"
)

var tmpDir string
var testHost = "localhost,127.0.0.1"
var tlsConfig *tls.Config

//var useTls = false
var useTls = true

func TestMain(m *testing.M) {
	setUp()

	code := m.Run()

	tearDown()

	os.Exit(code)
}

func setUp() {
	dir, err := ioutil.TempDir("", "ece")
	if err != nil {
		fmt.Printf("Error creating temp dir %q: %s\n", tmpDir, err)
		os.Exit(1)
	}

	tmpDir = dir

	crtFile := fmt.Sprintf("%s/cert.pem", tmpDir)
	keyFile := fmt.Sprintf("%s/key.pem", tmpDir)

	err = makeTestCert(testHost, crtFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to set up test certs: %s", err)
	}

	if useTls {
		err = os.Setenv(ECE_TLS_CRT_PATH_ENV_VAR, crtFile)
		if err != nil {
			log.Fatalf("Failed to set env var %s", ECE_TLS_CRT_PATH_ENV_VAR)
		}

		err = os.Setenv(ECE_TLS_KEY_PATH_ENV_VAR, keyFile)
		if err != nil {
			log.Fatalf("Failed to set env var %s", ECE_TLS_KEY_PATH_ENV_VAR)
		}

		roots := x509.NewCertPool()

		rootPEMBytes, err := ioutil.ReadFile(crtFile)
		if err != nil {
			log.Fatalf("failed to read %s: %s", crtFile, err)
		}

		ok := roots.AppendCertsFromPEM(rootPEMBytes)
		if !ok {
			log.Fatalf("failed to read root PEM Bytes")
		}

		tlsConfig = &tls.Config{
			RootCAs: roots,
		}
	}
}

func tearDown() {
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		_ = os.Remove(tmpDir)
	}
}

//func TestUnmarshalWaf(t *testing.T) {
//	waf, err := UnmarshalWaf(testWafEntryMessage())
//	if err != nil {
//		fmt.Printf("Error unmarshalling waf json: %s", err)
//		t.Fail()
//	}
//
//	assert.Equal(t, testWafEntry(), waf, "Unmarshaled waf object meets expectations.")
//
//	_, err = UnmarshalWaf(testWebEntryMessage())
//	if err == nil {
//		fmt.Printf("Web entry successfully unmarshalled as a Waf Entry.  Booh.")
//		t.Fail()
//	}
//}
//
//func TestUnmarshalWeb(t *testing.T) {
//	web, err := UnmarshalWeb(testWebEntryMessage())
//	if err != nil {
//		fmt.Printf("Error unmarshalling web json: %s", err)
//		t.Fail()
//	}
//
//	assert.Equal(t, testWebEntry(), web, "Unmarshaled web object meets expectations.")
//
//	_, err = UnmarshalWeb(testWafEntryMessage())
//	if err == nil {
//		fmt.Printf("Web entry successfully unmarshalled as a Waf Entry.  Booh.")
//		t.Fail()
//	}
//}

var testinputs = []struct {
	name string
	in   []string
	out  []OutputEvent
}{
	{
		"web-then-waf",
		[]string{testWebEntryMessage(), testWafEntryMessage()},
		[]OutputEvent{testOutputEvent()},
	},
	//{
	//	"waf-only",
	//	[]string{testWafEntryMessage()},
	//
	//	[]OutputEvent{
	//		{
	//			RequestId: "65df6a015f5a85fdf3559acad090ce1c567cbceacefea4baa476406b1d876392",
	//			RuleIds:   []int{0},
	//			WafEvents: []OutputWaf{
	//				{
	//					RuleId:       "0",
	//					Severity:     "99",
	//					AnomalyScore: "0",
	//					LogData:      "",
	//					WafMessage:   "",
	//				},
	//			},
	//		},
	//	},
	//},
}

func TestParse(t *testing.T) {
	for _, tc := range testinputs {
		t.Run(tc.name, func(t *testing.T) {
			ece, logs := testServer()

			err := sendSyslog("", tc.in, ece.Address, tlsConfig)
			if err != nil {
				log.Printf("failed sending syslog data: %s", err)
				t.Fail()
			}
			ok, message := within(time.Second, func() (bool, string) {
				return compareOutput(logs.String(), tc.out)
			})
			if !ok {
				t.Error(message)
				t.Fail()
			}
			err = ece.Shutdown()
			if err != nil {
				log.Printf("Error shutting down server: %s", err)
			}
			ece.Wait()
		})
	}
}

// TestTTL sends the same request twice after waiting for the TTL to expire
//func TestTTL(t *testing.T) {
//	ece, logs := testServer()
//
//	err := sendSyslog("", []string{
//		testWebEntryMessage(),
//		testWafEntryMessage(),
//	}, ece.Address, tlsConfig)
//	if err != nil {
//		t.Error("send syslog", err)
//	}
//
//	time.Sleep(ece.Ttl)
//
//	err = sendSyslog("", []string{
//		testWebEntryMessage(),
//		testWafEntryMessage(),
//		`{"event_type":"req","request_id":"00"}`,
//	}, ece.Address, tlsConfig)
//	if err != nil {
//		t.Error("send syslog", err)
//	}
//
//	ok, message := within(time.Second, func() (bool, string) {
//		return compareOutput(logs.String(), []OutputEvent{
//			testOutputEvent(),
//			testOutputEvent(),
//			OutputEvent{RequestId: "00", RuleIds: []int{}},
//		})
//	})
//	if !ok {
//		t.Error(message)
//	}
//
//	ece.Shutdown()
//	ece.Wait()
//}
