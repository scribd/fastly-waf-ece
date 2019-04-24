package service

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestWebThenWaf(t *testing.T) {
	s, logs, err := startServers()
	if err != nil {
		t.Error("start_error:", err)
		return
	}

	err = sendSyslog("", []string{
		TestWebEntryMessage(),
		TestWafEntryMessage(),
	})
	if err != nil {
		t.Error("send syslog", err)
	}

	ok, message := within(time.Second, func() (bool, string) {
		return compareOutput(logs.String(), []OutputEvent{TestOutputEvent()})
	})
	if !ok {
		t.Error(message)
	}

	s.Shutdown()
	s.Wait()
}

func TestWafOnly(t *testing.T) {
	s, logs, err := startServers()
	if err != nil {
		t.Error("start_error:", err)
		return
	}

	err = sendSyslog("", []string{
		TestWafEntryMessage(),
	})
	if err != nil {
		t.Error("send syslog", err)
	}

	ok, message := within(time.Second, func() (bool, string) {
		return compareOutput(logs.String(),
			[]OutputEvent{
				{
					RequestId: "65df6a015f5a85fdf3559acad090ce1c567cbceacefea4baa476406b1d876392",
					RuleIds:   []int{0},
					WafEvents: []OutputWaf{
						{
							RuleId:       "0",
							Severity:     "99",
							AnomalyScore: "0",
							LogData:      "",
							WafMessage:   "",
						},
					},
				},
			})
	})
	if !ok {
		t.Error(message)
	}

	s.Shutdown()
	s.Wait()
}

func TestSameRequestDelayed(t *testing.T) {
	s, logs, err := startServers()
	if err != nil {
		t.Error("start_error:", err)
		return
	}

	err = sendSyslog("", []string{
		TestWebEntryMessage(),
		TestWafEntryMessage(),
	})
	if err != nil {
		t.Error("send syslog", err)
	}

	time.Sleep(s.Ttl)

	err = sendSyslog("", []string{
		TestWebEntryMessage(),
		TestWafEntryMessage(),
		`{"event_type":"req","request_id":"00"}`,
	})
	if err != nil {
		t.Error("send syslog", err)
	}

	ok, message := within(time.Second, func() (bool, string) {
		return compareOutput(logs.String(), []OutputEvent{
			TestOutputEvent(),
			TestOutputEvent(),
			OutputEvent{RequestId: "00", RuleIds: []int{}},
		})
	})
	if !ok {
		t.Error(message)
	}

	s.Shutdown()
	s.Wait()
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
