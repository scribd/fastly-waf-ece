package ece

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
	TlsProtocol          string `json:"tls_protocol"`
	TlsCipher            string `json:"tls_cipher"`
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
	TlsProtocol          string      `json:"tls_protocol"`
	TlsCipher            string      `json:"tls_cipher"`
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
	Events  map[string]*Event
	logger  *log.Logger
	Ttl     time.Duration
	Debug   bool
	Address string

	server *syslog.Server
}

// NewECE  Creates a new ECE.
func NewECE(maxAge time.Duration, logFile string, maxLogSize int, maxLogBackups int, maxLogAge int, logCompress bool, address string) *ECE {
	logObj := log.New(os.Stdout, "", 0)

	logObj.SetOutput(&lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    maxLogSize,
		MaxBackups: maxLogBackups,
		MaxAge:     maxLogAge,
		Compress:   logCompress,
	})

	ece := &ECE{
		Ttl:     maxAge,
		logger:  logObj,
		Events:  make(map[string]*Event),
		Address: address,
	}

	return ece
}

// RetrieveEvent returns the event for the request id, or nil if it doesn't exist
func (ece *ECE) RetrieveEvent(reqId string) *Event {
	ece.RLock()
	event, exists := ece.Events[reqId]
	ece.RUnlock()

	if !exists {
		ece.Lock()
		// Double check that someone hasn't inserted the event,
		// while we didn't hold a lock
		event, exists = ece.Events[reqId]
		if exists {
			ece.Unlock()
			// Other thread beat us to it, bail out
			return event
		}

		// New event, insert an empty record and schedule a write
		event = &Event{}

		ece.Events[reqId] = event
		ece.Unlock()

		go ece.DelayNotify(reqId)
	}

	return event
}

// WriteEvent writes the event to the log
func (ece *ECE) WriteEvent(reqId string) (err error) {
	event := ece.RemoveEvent(reqId)

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
			TlsCipher:            event.RequestEntries[0].TlsCipher,
			TlsProtocol:          event.RequestEntries[0].TlsProtocol,
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

	ece.logger.Println(string(outputBytes))

	return err
}

// RemoveEvent removes the event from the internal cache
func (ece *ECE) RemoveEvent(reqId string) *Event {
	ece.Lock()
	e := ece.Events[reqId]
	delete(ece.Events, reqId)
	ece.Unlock()

	return e
}

// AddEvent parses the event text, then looks it up in the internal cache.  If it's there, it adds the appropriate record to the existing event.  If not, it creates one and sets it's timeout.
func (ece *ECE) AddEvent(message string) (err error) {
	waf, err := UnmarshalWaf(message) // Try to unmarshal the message into a WAF event
	if err != nil {                   // It didn't unmarshal.  It's either a req event, or garbage
		return ece.addWebEvent(message)
	}

	// Ok, it's a Waf event.  Process it as such.
	event := ece.RetrieveEvent(waf.RequestId)

	// it does exist, add to it's waf list
	//fmt.Printf("\tAdding Waf to %q\n", waf.RequestId)
	event.mutex.Lock()
	event.WafEntries = append(event.WafEntries, waf)
	event.mutex.Unlock()

	return err
}

func (ece *ECE) addWebEvent(message string) (err error) {
	req, err := UnmarshalWeb(message)

	if err != nil { // It didn't unmarshal as a req event either.
		err = fmt.Errorf("failed unmarshalling data in web event: %s\n", message)
		return err
	}

	if ece.Debug {
		_, _ = fmt.Fprintf(os.Stderr, "Web Event ID: %q\n", req.RequestId)
	}

	event := ece.RetrieveEvent(req.RequestId)

	// it does exist, add to it's req list
	event.mutex.Lock()

	if ece.Debug {
		_, _ = fmt.Fprintf(os.Stderr, "\tAdding Web to %q\n", req.RequestId)
	}
	event.RequestEntries = append(event.RequestEntries, req)
	event.mutex.Unlock()

	return err
}

func (ece *ECE) Start() (err error) {
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			message := logParts["message"].(string)
			if ece.Debug {
				_, _ = fmt.Fprintf(os.Stderr, "Message Received: %s", message)
			}
			err := ece.AddEvent(message)
			if err != nil {
				log.Printf("Error: %s", err)
			}
		}
	}(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.RFC5424)
	server.SetHandler(handler)

	// The syslog server package github.com/mcuardros/go-syslog appears to expect that if you use TLS at all, you're using it both in the Server sense, i.e. the Syslog server has a TLS cert on it and we have an encrypted tunnel between the client and the server, and also in that you're using TLS Client certs.  These are, unfortunately, 2 different things.
	// The only way to use TLS on the server and encrypt the channel and NOT use client certs (Not sure that Fastly supports this) is to set this SetTlsPeerNameFunc to nil (or alternately make a function always return true)
	server.SetTlsPeerNameFunc(nil)
	//server.SetTlsPeerNameFunc(func(tlsConn *tls.Conn)(tlsPeer string, ok bool){
	//	return "", true
	//})

	if os.Getenv(ECE_TLS_CRT_PATH_ENV_VAR) != "" && os.Getenv(ECE_TLS_KEY_PATH_ENV_VAR) != "" {
		_, _ = fmt.Fprintf(os.Stderr, "TLS Enabled.  Key: %s  Cert: %s\n", os.Getenv(ECE_TLS_CRT_PATH_ENV_VAR), os.Getenv(ECE_TLS_KEY_PATH_ENV_VAR))

		keypair, err := tls.LoadX509KeyPair(os.Getenv(ECE_TLS_CRT_PATH_ENV_VAR), os.Getenv(ECE_TLS_KEY_PATH_ENV_VAR))
		if err != nil {
			err = errors.Wrapf(err, "failed to load TLS Cert and Key from %s and %s", ECE_TLS_KEY_PATH_ENV_VAR, ECE_TLS_KEY_PATH_ENV_VAR)
			return err
		}

		config := tls.Config{
			Certificates: []tls.Certificate{keypair},
		}

		err = server.ListenTCPTLS(ece.Address, &config)
		if err != nil {
			err = errors.Wrapf(err, "failed to start TLS TCP listener")
			return err
		}

	} else {
		err := server.ListenTCP(ece.Address)
		if err != nil {
			err = errors.Wrapf(err, "failed to start TCP listener")
			return err
		}
	}

	err = server.Boot()
	if err != nil {
		err = errors.Wrapf(err, "server failed to boot")
		return err
	}

	ece.server = server

	_, _ = fmt.Fprint(os.Stderr, "Fastly WAF Event Correlation Engine starting!\n")
	_, _ = fmt.Fprintf(os.Stderr, "Listening on %s\n", ece.Address)
	_, _ = fmt.Fprintf(os.Stderr, "TTL: %f seconds\n", ece.Ttl.Seconds())

	return err
}

func (ece *ECE) Shutdown() (err error) {
	err = ece.server.Kill()
	if err != nil {
		err = errors.Wrapf(err, "failed to kill server")
	}

	return err
}

func (ece *ECE) Wait() {
	ece.server.Wait()
}

//DelayNotify is intended to run from a goroutine.  It sets a timer equal to the ttl, and then writes the event after the timer expires.
func (ece *ECE) DelayNotify(reqId string) {
	time.Sleep(ece.Ttl)

	err := ece.WriteEvent(reqId)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error in DelayNotify: %s\n", err)
	}
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
