package service

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUnmarshalWaf(t *testing.T) {
	waf, err := UnmarshalWaf(TestWafEntryMessage())
	if err != nil {
		fmt.Printf("Error unmarshalling waf json: %s", err)
		t.Fail()
	}

	assert.Equal(t, TestWafEntry(), waf, "Unmarshaled waf object meets expectations.")

	_, err = UnmarshalWaf(TestWebEntryMessage())
	if err == nil {
		fmt.Printf("Web entry successfully unmarshalled as a Waf Entry.  Booh.")
		t.Fail()
	}
}

func TestUnmarshalWeb(t *testing.T) {
	web, err := UnmarshalWeb(TestWebEntryMessage())
	if err != nil {
		fmt.Printf("Error unmarshalling web json: %s", err)
		t.Fail()
	}

	assert.Equal(t, TestWebEntry(), web, "Unmarshaled web object meets expectations.")

	_, err = UnmarshalWeb(TestWafEntryMessage())
	if err == nil {
		fmt.Printf("Web entry successfully unmarshalled as a Waf Entry.  Booh.")
		t.Fail()
	}
}
