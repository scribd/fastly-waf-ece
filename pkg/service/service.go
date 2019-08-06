package service

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/mcuadros/go-syslog.v2"
	"gopkg.in/natefinch/lumberjack.v2"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

const ECE_TLS_CRT_PATH_ENV_VAR = "ECE_TLS_CRT_PATH"
const ECE_TLS_KEY_PATH_ENV_VAR = "ECE_TLS_KEY_PATH"

// Event Struct representing an entire firewall event, containing generally 1 web event and 0 or more waf events
type Event struct {
	mutex sync.Mutex

	WafEntries     []WafEntry
	RequestEntries []RequestEntry
}

// WafEntry  a struct representing a Waf Log Entry
type WafEntry struct {
	EventType    string `json:"event_type"`
	RequestId    string `json:"request_id"`
	RuleId       string `json:"rule_id"`
	Severity     string `json:"severity"`
	AnomalyScore string `json:"anomaly_score"`
	LogData      string `json:"logdata"`
	WafMessage   string `json:"waf_message"`
}

// RequestEntry a struct representing a Web Event
type RequestEntry struct {
	EventType            string `json:"event_type"`
	ServiceId            string `json:"service_id"`
	RequestId            string `json:"request_id"`
	StartTime            string `json:"start_time"`
	FastlyInfo           string `json:"fastly_info"`
	Datacenter           string `json:"datacenter"`
	ClientIp             string `json:"client_ip"`
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
	SqlInjectionScore    string `json:"sql_injection_score"`
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
	ThrottlingRule       string `json:"throttling_rule"`
}

// OutputEvent is simply the marshal format for the outputted merged event
type OutputEvent struct {
	ServiceId            string      `json:"service_id"`
	RequestId            string      `json:"request_id"`
	StartTime            string      `json:"start_time"`
	FastlyInfo           string      `json:"fastly_info"`
	Datacenter           string      `json:"datacenter"`
	ClientIp             string      `json:"client_ip"`
	ReqMethod            string      `json:"req_method"`
	ReqURI               string      `json:"req_uri"`
	ReqHHost             string      `json:"req_h_host"`
	ReqHUserAgent        string      `json:"req_h_user_agent"`
	ReqHAcceptEncoding   string      `json:"req_h_accept_encoding"`
	ReqHeaderBytes       string      `json:"req_header_bytes"`
	ReqBodyBytes         string      `json:"req_body_bytes"`
	RuleIds              []int       `json:"rule_ids"`
	WafLogged            string      `json:"waf_logged"`
	WafBlocked           string      `json:"waf_blocked"`
	WafFailures          string      `json:"waf_failures"`
	WafExecuted          string      `json:"waf_executed"`
	AnomalyScore         string      `json:"anomaly_score"`
	SqlInjectionScore    string      `json:"sql_injection_score"`
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
	ThrottlingRule       string      `json:"throttling_rule"`
	Throttled            int         `json:"throttled"`
}

// OutputWaf is the output format for the waf event
type OutputWaf struct {
	RuleId       string `json:"rule_id"`
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
	Ttl    time.Duration
	Debug  bool

	server *syslog.Server
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
		Ttl:    maxAge,
		logger: logObj,
		Events: make(map[string]*Event),
	}

	return a
}

// RetrieveEvent returns the event for the request id, or nil if it doesn't exist
func (engine *ECE) RetrieveEvent(reqId string) *Event {
	engine.RLock()
	e, exists := engine.Events[reqId]
	engine.RUnlock()

	if !exists {
		engine.Lock()
		// Double check that someone hasn't inserted the event,
		// while we didn't hold a lock
		e, exists = engine.Events[reqId]
		if exists {
			engine.Unlock()
			// Other thread beat us to it, bail out
			return e
		}

		// New event, insert an empty record and schedule a write
		e = &Event{}

		engine.Events[reqId] = e
		engine.Unlock()

		go engine.DelayNotify(reqId)
	}

	return e
}

// WriteEvent writes the event to the log
func (engine *ECE) WriteEvent(reqId string) (err error) {
	event := engine.RemoveEvent(reqId)

	// Lock, to prevent any modification, but no real need to unlock
	event.mutex.Lock()

	var outputEvent OutputEvent

	if len(event.RequestEntries) > 0 {
		outputEvent = OutputEvent{
			ServiceId:            event.RequestEntries[0].ServiceId,
			RequestId:            event.RequestEntries[0].RequestId,
			StartTime:            event.RequestEntries[0].StartTime,
			FastlyInfo:           event.RequestEntries[0].FastlyInfo,
			Datacenter:           event.RequestEntries[0].Datacenter,
			ClientIp:             event.RequestEntries[0].ClientIp,
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
			SqlInjectionScore:    event.RequestEntries[0].SqlInjectionScore,
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
			ThrottlingRule:       event.RequestEntries[0].ThrottlingRule,
		}
	} else {
		outputEvent = OutputEvent{
			RequestId: reqId,
		}
	}

	// map to hold unique violated rule ids
	ruleIds := make(map[string]int)

	for _, wafEvent := range event.WafEntries {
		var decoded string
		if wafEvent.LogData != "" {
			decodedBytes, _ := base64.StdEncoding.DecodeString(wafEvent.LogData)
			decoded = string(decodedBytes)
		}

		wafOut := OutputWaf{
			RuleId:       wafEvent.RuleId,
			Severity:     wafEvent.Severity,
			AnomalyScore: wafEvent.AnomalyScore,
			LogData:      decoded,
			WafMessage:   wafEvent.WafMessage,
		}

		outputEvent.WafEvents = append(outputEvent.WafEvents, wafOut)

		ruleIds[wafEvent.RuleId] = 1
	}

	// make a list from the keys
	ids := make([]int, len(ruleIds))

	i := 0
	for id := range ruleIds {
		number, err := strconv.Atoi(id)
		if err != nil {
			err = errors.Wrapf(err, "error converting %s to integer", id)
			return err
		}

		ids[i] = number
		i++
	}

	outputEvent.RuleIds = ids

	if outputEvent.ThrottlingRule != "" {
		outputEvent.Throttled = 1
	}

	outputBytes, err := json.Marshal(outputEvent)

	if err != nil {
		err = errors.Wrapf(err, "failed to marshall output for req id %q", reqId)
		return err
	}

	engine.logger.Println(string(outputBytes))

	return err
}

// RemoveEvent removes the event from the internal cache
func (engine *ECE) RemoveEvent(reqId string) *Event {
	engine.Lock()
	e := engine.Events[reqId]
	delete(engine.Events, reqId)
	engine.Unlock()

	return e
}

// AddEvent parses the event text, then looks it up in the internal cache.  If it's there, it adds the appropriate record to the existing event.  If not, it creates one and sets it's timeout.
func (engine *ECE) AddEvent(message string) (err error) {
	waf, err := UnmarshalWaf(message) // Try to unmarshal the message into a WAF event
	if err != nil {                   // It didn't unmarshal.  It's either a req event, or garbage
		return engine.addWebEvent(message)
	}

	// Ok, it's a Waf event.  Process it as such.
	event := engine.RetrieveEvent(waf.RequestId)

	// it does exist, add to it's waf list
	//fmt.Printf("\tAdding Waf to %q\n", waf.RequestId)
	event.mutex.Lock()
	event.WafEntries = append(event.WafEntries, waf)
	event.mutex.Unlock()

	return err
}

func (engine *ECE) addWebEvent(message string) (err error) {
	req, err := UnmarshalWeb(message)

	if err != nil { // It didn't unmarshal as a req event either.
		err = fmt.Errorf("unparsable data: %s", message)
		return err
	}

	//log.Printf("WEb Event ID: %q", waf.RequestId)

	event := engine.RetrieveEvent(req.RequestId)

	// it does exist, add to it's req list
	event.mutex.Lock()
	//fmt.Printf("\tAdding Web to %q\n", req.RequestId)
	event.RequestEntries = append(event.RequestEntries, req)
	event.mutex.Unlock()

	return err
}

func (engine *ECE) Start(address string) {
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

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

	server := syslog.NewServer()
	server.SetFormat(syslog.RFC5424)
	server.SetHandler(handler)

	if os.Getenv(ECE_TLS_CRT_PATH_ENV_VAR) != "" && os.Getenv(ECE_TLS_KEY_PATH_ENV_VAR) != "" {
		keypair, err := tls.LoadX509KeyPair(os.Getenv(ECE_TLS_CRT_PATH_ENV_VAR), os.Getenv(ECE_TLS_KEY_PATH_ENV_VAR))
		if err != nil {
			log.Fatalf("failed to load TLS Cert and Key from %s and %s", ECE_TLS_KEY_PATH_ENV_VAR, ECE_TLS_KEY_PATH_ENV_VAR)
		}

		config := tls.Config{
			Certificates: []tls.Certificate{keypair},
		}

		server.ListenTCPTLS(address, &config)

	} else {
		server.ListenTCP(address)
	}

	server.Boot()

	engine.server = server
}

// Run runs the syslog server that waits for events
func (engine *ECE) Run(address string) {
	engine.Start(address)

	fmt.Fprint(os.Stderr, "Fastly WAF Event Correlation Engine starting!\n")
	fmt.Fprintf(os.Stderr, "Listening on %s\n", address)
	fmt.Fprintf(os.Stderr, "TTL: %f seconds\n", engine.Ttl.Seconds())
	if os.Getenv(ECE_TLS_CRT_PATH_ENV_VAR) != "" && os.Getenv(ECE_TLS_KEY_PATH_ENV_VAR) != "" {
		fmt.Fprintf(os.Stderr, "TLS Enabled.  Key: %s  Cert: %s\n", ECE_TLS_CRT_PATH_ENV_VAR, ECE_TLS_KEY_PATH_ENV_VAR)
	}

	engine.Wait()
}

func (engine *ECE) Shutdown() {
	engine.server.Kill()
}

func (engine *ECE) Wait() {
	engine.server.Wait()
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
func (ece *ECE) DelayNotify(reqId string) {
	time.Sleep(ece.Ttl)

	err := ece.WriteEvent(reqId)
	if err != nil {
	}
}
