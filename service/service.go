package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/mcuadros/go-syslog.v2"
	"gopkg.in/natefinch/lumberjack.v2"
	"log"
	"os"
	"sync"
	"time"
)

// Event Struct representing an entire firewall event, containing generally 1 web event and 0 or more waf events
type Event struct {
	WafEntries     []WafEntry
	RequestEntries []RequestEntry
}

// WafEntry  a struct representing a Waf Log Entry
type WafEntry struct {
	EventType    string `json:"event_type"`
	RequestID    string `json:"request_id"`
	RuleID       string `json:"rule_id"`
	Severity     string `json:"severity"`
	AnomalyScore string `json:"anomaly_score"`
	LogData      string `json:"logdata"`
	WafMessage   string `json:"waf_message"`
}

// RequestEntry a struct representing a Web Event
type RequestEntry struct {
	EventType            string `json:"event_type"`
	ServiceID            string `json:"service_id"`
	RequestID            string `json:"request_id"`
	StartTime            string `json:"start_time"`
	FastlyInfo           string `json:"fastly_info"`
	Datacenter           string `json:"datacenter"`
	ClientIP             string `json:"client_ip"`
	ReqMethod            string `json:"req_method"`
	ReqURI               string `json:"req_uri"`
	ReqHHost             string `json:"req_h_host"`
	ReqHUserAgent        string `json:"req_h_user_agent"`
	ReqHAcceptEncoding   string `json:"req_h_accept_encoding"`
	ReqHeaderBytes       string `json:"req_header_bytes"`
	ReqBodyBytes         string `json:"req_body_bytes"`
	WafLogged            string `json:"waf_logged"`
	WafBlocked           string `json:"waf_blocked"`
	WafFailures          string `json:"waf_failures"`
	WafExecuted          string `json:"waf_executed"`
	AnomalyScore         string `json:"anomaly_score"`
	SQLInjectionScore    string `json:"sql_injection_score"`
	RfiScore             string `json:"rfi_score"`
	LfiScore             string `json:"lfi_score"`
	RceScore             string `json:"rce_score"`
	PhpInjectionScore    string `json:"php_injection_score"`
	SessionFixationScore string `json:"session_fixation_score"`
	HTTPViolationScore   string `json:"http_violation_score"`
	XSSScore             string `json:"xss_score"`
	RespStatus           string `json:"resp_status"`
	RespBytes            string `json:"resp_bytes"`
	RespHeaderBytes      string `json:"resp_header_bytes"`
	RespBodyBytes        string `json:"resp_body_bytes"`
}

// OutputEvent is simply the marshal format for the outputted merged event
type OutputEvent struct {
	ServiceID            string      `json:"service_id"`
	RequestID            string      `json:"request_id"`
	StartTime            string      `json:"start_time"`
	FastlyInfo           string      `json:"fastly_info"`
	Datacenter           string      `json:"datacenter"`
	ClientIP             string      `json:"client_ip"`
	ReqMethod            string      `json:"req_method"`
	ReqURI               string      `json:"req_uri"`
	ReqHHost             string      `json:"req_h_host"`
	ReqHUserAgent        string      `json:"req_h_user_agent"`
	ReqHAcceptEncoding   string      `json:"req_h_accept_encoding"`
	ReqHeaderBytes       string      `json:"req_header_bytes"`
	ReqBodyBytes         string      `json:"req_body_bytes"`
	WafLogged            string      `json:"waf_logged"`
	WafBlocked           string      `json:"waf_blocked"`
	WafFailures          string      `json:"waf_failures"`
	WafExecuted          string      `json:"waf_executed"`
	AnomalyScore         string      `json:"anomaly_score"`
	SQLInjectionScore    string      `json:"sql_injection_score"`
	RfiScore             string      `json:"rfi_score"`
	LfiScore             string      `json:"lfi_score"`
	RceScore             string      `json:"rce_score"`
	PhpInjectionScore    string      `json:"php_injection_score"`
	SessionFixationScore string      `json:"session_fixation_score"`
	HTTPViolationScore   string      `json:"http_violation_score"`
	XSSScore             string      `json:"xss_score"`
	RespStatus           string      `json:"resp_status"`
	RespBytes            string      `json:"resp_bytes"`
	RespHeaderBytes      string      `json:"resp_header_bytes"`
	RespBodyBytes        string      `json:"resp_body_bytes"`
	WafEvents            []OutputWaf `json:"waf_events"`
}

// OutputWaf is the output format for the waf event
type OutputWaf struct {
	RuleID       string `json:"rule_id"`
	Severity     string `json:"severity"`
	AnomalyScore string `json:"anomaly_score"`
	LogData      string `json:"logdata"`
	WafMessage   string `json:"waf_message"`
}

// ECE The Event Correlation Engine itself
type ECE struct {
	sync.RWMutex
	Events map[string]*Event
	logger *log.Logger
	TTL    time.Duration
	Debug  bool
}

// NewECE  Creates a new ECE.
func NewECE(maxAge time.Duration, logFile string, maxLogSize int, maxLogBackups int, maxLogAge int, logCompress bool) *ECE {
	logObj := log.New(os.Stdout, "", 0)

	logObj.SetOutput(&lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    maxLogSize,
		MaxBackups: maxLogBackups,
		MaxAge:     maxLogAge,
		Compress:   logCompress,
	})

	a := &ECE{
		TTL:    maxAge,
		logger: logObj,
		Events: make(map[string]*Event),
	}

	return a
}

// RetrieveEvent returns the event for the request id, or nil if it doesn't exist
func (engine *ECE) RetrieveEvent(reqID string) *Event {
	engine.RLock()
	e, exists := engine.Events[reqID]
	engine.RUnlock()

	if exists {
		return e
	}

	return nil
}

// WriteEvent writes the event to Elasticsearch
func (engine *ECE) WriteEvent(reqID string) (err error) {
	event := engine.RetrieveEvent(reqID)

	var outputEvent OutputEvent

	if len(event.RequestEntries) > 0 {
		outputEvent = OutputEvent{
			ServiceID:            event.RequestEntries[0].ServiceID,
			RequestID:            event.RequestEntries[0].RequestID,
			StartTime:            event.RequestEntries[0].StartTime,
			FastlyInfo:           event.RequestEntries[0].FastlyInfo,
			Datacenter:           event.RequestEntries[0].Datacenter,
			ClientIP:             event.RequestEntries[0].ClientIP,
			ReqMethod:            event.RequestEntries[0].ReqMethod,
			ReqURI:               event.RequestEntries[0].ReqURI,
			ReqHHost:             event.RequestEntries[0].ReqHHost,
			ReqHUserAgent:        event.RequestEntries[0].ReqHUserAgent,
			ReqHAcceptEncoding:   event.RequestEntries[0].ReqHAcceptEncoding,
			ReqHeaderBytes:       event.RequestEntries[0].ReqHeaderBytes,
			ReqBodyBytes:         event.RequestEntries[0].ReqBodyBytes,
			WafLogged:            event.RequestEntries[0].WafLogged,
			WafBlocked:           event.RequestEntries[0].WafBlocked,
			WafFailures:          event.RequestEntries[0].WafFailures,
			WafExecuted:          event.RequestEntries[0].WafExecuted,
			AnomalyScore:         event.RequestEntries[0].AnomalyScore,
			SQLInjectionScore:    event.RequestEntries[0].SQLInjectionScore,
			RfiScore:             event.RequestEntries[0].RfiScore,
			LfiScore:             event.RequestEntries[0].LfiScore,
			RceScore:             event.RequestEntries[0].RceScore,
			PhpInjectionScore:    event.RequestEntries[0].PhpInjectionScore,
			SessionFixationScore: event.RequestEntries[0].SessionFixationScore,
			HTTPViolationScore:   event.RequestEntries[0].HTTPViolationScore,
			XSSScore:             event.RequestEntries[0].XSSScore,
			RespStatus:           event.RequestEntries[0].RespStatus,
			RespBytes:            event.RequestEntries[0].RespBytes,
			RespHeaderBytes:      event.RequestEntries[0].RespHeaderBytes,
			RespBodyBytes:        event.RequestEntries[0].RespBodyBytes,
			WafEvents:            make([]OutputWaf, 0),
		}
	} else {
		outputEvent = OutputEvent{
			WafEvents: make([]OutputWaf, 0),
		}
	}

	for _, wafEvent := range event.WafEntries {
		var decoded string
		if wafEvent.LogData != "" {
			decodedBytes, _ := base64.StdEncoding.DecodeString(wafEvent.LogData)
			decoded = string(decodedBytes)
		}

		wafOut := OutputWaf{
			RuleID:       wafEvent.RuleID,
			Severity:     wafEvent.Severity,
			AnomalyScore: wafEvent.AnomalyScore,
			LogData:      decoded,
			WafMessage:   wafEvent.WafMessage,
		}

		outputEvent.WafEvents = append(outputEvent.WafEvents, wafOut)
	}

	outputBytes, err := json.Marshal(outputEvent)

	if err != nil {
		err = errors.Wrapf(err, "failed to marshall output for req id %q", reqID)
		return err
	}

	engine.logger.Println(string(outputBytes))

	err = engine.RemoveEvent(reqID)
	if err != nil {
		log.Printf("Error removing: %s", err)
	}

	return err
}

// RemoveEvent removes the event from the internal cache
func (engine *ECE) RemoveEvent(reqID string) (err error) {
	engine.Lock()
	delete(engine.Events, reqID)
	engine.Unlock()

	return err
}

// AddEvent parses the event text, then looks it up in the internal cache.  If it's there, it adds the appropriate record to the existing event.  If not, it creates one and sets it's timeout.
func (engine *ECE) AddEvent(message string) (err error) {
	waf, err := UnmarshalWaf(message) // Try to unmarshal the message into a WAF event
	if err != nil {                   // It didn't unmarshal.  It's either a req event, or garbage
		req, err := UnmarshalWeb(message)

		if err != nil { // It didn't unmarshal as a req event either.
			err = fmt.Errorf("unparsable data: %s", message)
			return err
		}

		//log.Printf("WEb Event ID: %q", waf.RequestID)

		event := engine.RetrieveEvent(req.RequestID)

		if event == nil { // It doesn't exist, create it and set it's lifetime
			event := Event{
				WafEntries:     make([]WafEntry, 0),
				RequestEntries: make([]RequestEntry, 0),
			}

			event.RequestEntries = append(event.RequestEntries, req)

			//fmt.Printf("New Web %q\n", req.RequestID)
			engine.Lock()
			engine.Events[req.RequestID] = &event
			engine.Unlock()

			// then set it to notify after ttl expires
			go DelayNotify(engine, req.RequestID)

			return err
		}

		// it does exist, add to it's req list
		engine.Lock()
		//fmt.Printf("\tAdding Web to %q\n", req.RequestID)
		event.RequestEntries = append(event.RequestEntries, req)
		engine.Unlock()

		return err
	}

	// Ok, it's a Waf event.  Process it as such.
	event := engine.RetrieveEvent(waf.RequestID)

	if event == nil { // It doesn't exist, create it and set it's lifetime
		event := Event{
			WafEntries:     make([]WafEntry, 0),
			RequestEntries: make([]RequestEntry, 0),
		}

		event.WafEntries = append(event.WafEntries, waf)

		//fmt.Printf("New Waf %q\n", waf.RequestID)
		engine.Lock()
		engine.Events[waf.RequestID] = &event
		engine.Unlock()

		// then set it to notify after ttl expires
		go DelayNotify(engine, waf.RequestID)

		return err
	}

	// it does exist, add to it's waf list
	//fmt.Printf("\tAdding Waf to %q\n", waf.RequestID)
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

	fmt.Fprint(os.Stderr, "Fastly WAF Event Correlation Engine starting!\n")
	fmt.Fprintf(os.Stderr, "Listening on %s\n", address)
	fmt.Fprintf(os.Stderr, "TTL: %f seconds\n", engine.TTL.Seconds())

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			message := logParts["message"].(string)
			if engine.Debug {
				fmt.Fprintln(os.Stderr, message)
			}
			err := engine.AddEvent(message)
			if err != nil {
				log.Printf("Error: %s", err)
			}
		}
	}(channel)

	server.Wait()

}

// UnmarshalWaf unmarshals the log json into a WafEntry Object
func UnmarshalWaf(message string) (waf WafEntry, err error) {
	err = json.Unmarshal([]byte(message), &waf)
	if waf.EventType != "waf" {
		return WafEntry{}, errors.New("Not a waf entry")
	}

	return waf, err
}

// UnmarshalWeb unmarshals the log json into a RequestEntry Object
func UnmarshalWeb(message string) (web RequestEntry, err error) {
	err = json.Unmarshal([]byte(message), &web)
	if web.EventType != "req" {
		return RequestEntry{}, errors.New("Not a web entry")
	}
	return web, err
}

//DelayNotify is intended to run from a goroutine.  It sets a timer equal to the ttl, and then writes the event after the timer expires.
func DelayNotify(ece *ECE, reqID string) {
	timer := time.NewTimer(ece.TTL)
	defer timer.Stop()

	<-timer.C
	err := ece.WriteEvent(reqID)
	if err != nil {
		log.Printf("Error writing: %s", err)
	}
}
