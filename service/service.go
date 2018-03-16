package service

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/mcuadros/go-syslog.v2"
	"log"
	"os"
	"sync"
	"time"
)

// Event Struct representing an entire firewall event, containing generally 1 web event and 0 or more waf events
type Event struct {
	WafEntries []WafEntry
	WebEntries []WebEntry
}

// WafEntry  a struct representing a Waf Log Entry
type WafEntry struct {
	RequestId    string `json:"request_id"`
	EventType    string `json:"event_type"`
	AnomalyScore string `json:"anomaly_score"`
}

// WebEntry a struct representing a Web Event
type WebEntry struct {
	RequestId string `json:"request_id"`
	EventType string `json:"event_type"`
}

// ECE The Event Correlation Engine itself
type ECE struct {
	sync.RWMutex
	Events map[string]*Event
	logger *log.Logger
	Ttl    time.Duration
	Debug  bool
}

// NewECE  Creates a new ECE.
func NewECE(maxAge time.Duration) *ECE {
	logger := log.New(os.Stderr, "", 0)

	a := &ECE{
		Ttl:    maxAge,
		logger: logger,
		Events: make(map[string]*Event),
	}

	return a
}

// RetrieveEvent returns the event for the request id, or nil if it doesn't exist
func (engine *ECE) RetrieveEvent(reqId string) *Event {
	engine.RLock()
	e, exists := engine.Events[reqId]
	engine.RUnlock()

	if exists {
		return e
	}

	return nil
}

// WriteEvent writes the event to Elasticsearch
func (engine *ECE) WriteEvent(reqId string) (err error) {
	event := engine.RetrieveEvent(reqId)

	numWafs := len(event.WafEntries)
	numWebs := len(event.WebEntries)

	log.Printf("Request: %q  Request Entries: %d Waf Entries: %d", reqId, numWebs, numWafs)

	err = engine.RemoveEvent(reqId)
	if err != nil {
		log.Printf("Error removing: %s", err)
	}

	return err
}

// RemoveEvent removes the event from the internal cache
func (engine *ECE) RemoveEvent(reqId string) (err error) {
	engine.Lock()
	delete(engine.Events, reqId)
	engine.Unlock()

	return err
}

// AddEvent parses the event text, then looks it up in the internal cache.  If it's there, it adds the appropriate record to the existing event.  If not, it creates one and sets it's timeout.
func (engine *ECE) AddEvent(message string) (err error) {
	waf, err := UnmarshalWaf(message) // Try to unmarshal the message into a WAF event
	if err != nil {                   // It didn't unmarshal.  It's either a web event, or garbage
		web, err := UnmarshalWeb(message)

		if err != nil { // It didn't unmarshal as a web event either.
			err = fmt.Errorf("unparsable data: %s", message)
			return err
		}

		//log.Printf("WEb Event ID: %q", waf.RequestId)

		event := engine.RetrieveEvent(web.RequestId)

		if event == nil { // It doesn't exist, create it and set it's lifetime
			event := Event{
				WafEntries: make([]WafEntry, 0),
				WebEntries: make([]WebEntry, 0),
			}

			event.WebEntries = append(event.WebEntries, web)

			//fmt.Printf("New Web %q\n", web.RequestId)
			engine.Lock()
			engine.Events[web.RequestId] = &event
			engine.Unlock()

			// then set it to notify after ttl expires
			go DelayNotify(engine, web.RequestId)

			return err
		}

		// it does exist, add to it's web list
		engine.Lock()
		//fmt.Printf("\tAdding Web to %q\n", web.RequestId)
		event.WebEntries = append(event.WebEntries, web)
		engine.Unlock()

		return err
	}

	// Ok, it's a Waf event.  Process it as such.
	event := engine.RetrieveEvent(waf.RequestId)

	if event == nil { // It doesn't exist, create it and set it's lifetime
		event := Event{
			WafEntries: make([]WafEntry, 0),
			WebEntries: make([]WebEntry, 0),
		}

		event.WafEntries = append(event.WafEntries, waf)

		//fmt.Printf("New Waf %q\n", waf.RequestId)
		engine.Lock()
		engine.Events[waf.RequestId] = &event
		engine.Unlock()

		// then set it to notify after ttl expires
		go DelayNotify(engine, waf.RequestId)

		return err
	}

	// it does exist, add to it's waf list
	//fmt.Printf("\tAdding Waf to %q\n", waf.RequestId)
	engine.Lock()
	event.WafEntries = append(event.WafEntries, waf)
	engine.Unlock()

	return err
}

// Run runs the syslog server that waits for events
func (engine *ECE) Run(address string) {
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.RFC5424)
	server.SetHandler(handler)
	server.ListenTCP(address)
	server.Boot()

	log.Printf("Fastly WAF Event Correlation Engine starting!")
	log.Printf("Listening on %s", address)
	log.Printf("TTL: %f seconds", engine.Ttl.Seconds())

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			message := logParts["message"].(string)
			if engine.Debug {
				fmt.Println(message)
			}
			err := engine.AddEvent(message)
			if err != nil {
				log.Printf("Error: %s", err)
			}
		}
	}(channel)

	server.Wait()

}

func UnmarshalWaf(message string) (waf WafEntry, err error) {
	err = json.Unmarshal([]byte(message), &waf)
	if waf.EventType != "waf" {
		return WafEntry{}, errors.New("Not a waf entry")
	}

	return waf, err
}

func UnmarshalWeb(message string) (web WebEntry, err error) {
	err = json.Unmarshal([]byte(message), &web)
	if web.EventType != "req" {
		return WebEntry{}, errors.New("Not a web entry")
	}
	return web, err
}

//DelayNotify is intended to run from a goroutine.  It sets a timer equal to the ttl, and then writes the event after the timer expires.
func DelayNotify(ece *ECE, reqId string) {
	timer := time.NewTimer(ece.Ttl)
	defer timer.Stop()

	<-timer.C
	err := ece.WriteEvent(reqId)
	if err != nil {
		log.Printf("Error writing: %s", err)
	}
}
