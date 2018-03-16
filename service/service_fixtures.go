package service

// TestWafEntryMessage a canned example of a waf event log entry
func TestWafEntryMessage() string {
	return `{"event_type":"waf","request_id":"65df6a015f5a85fdf3559acad090ce1c567cbceacefea4baa476406b1d876392","rule_id":"0","severity":"99","anomaly_score":"0","logdata":"","waf_message":""}`

}

// TestWebEntryMessage a canned example of a request log entry
func TestWebEntryMessage() string {
	return `{"event_type":"req","service_id":"4RJF83V3byqFd7GlV2KC8b","request_id":"65df6a015f5a85fdf3559acad090ce1c567cbceacefea4baa476406b1d876392","start_time":"1521150005","fastly_info":"PASS","datacenter":"SFO","client_ip":"8.8.8.8","req_method":"POST","req_uri":"L2luZGV4Lmh0bWwK","req_h_host":"api.scribd.com","req_h_user_agent":"Zm9vLzEuMQo=","req_h_accept_encoding":"gzip","req_header_bytes":"338","req_body_bytes":"852","waf_logged":"0","waf_blocked":"0","waf_failures":"0","waf_executed":"1","anomaly_score":"0","sql_injection_score":"0","rfi_score":"0","lfi_score":"0","rce_score":"0","php_injection_score":"0","session_fixation_score":"0","http_violation_score":"0","xss_score":"0","resp_status":"200","resp_bytes":"697","resp_header_bytes":"620","resp_body_bytes":"77"}`
}

// TestWafEntry an example of a WafEntry Object
func TestWafEntry() WafEntry {
	return WafEntry{
		RequestId:    "65df6a015f5a85fdf3559acad090ce1c567cbceacefea4baa476406b1d876392",
		EventType:    "waf",
		AnomalyScore: "0",
	}
}

// TestWebEntry an example of a WebEntry Object
func TestWebEntry() WebEntry {
	return WebEntry{
		RequestId: "65df6a015f5a85fdf3559acad090ce1c567cbceacefea4baa476406b1d876392",
		EventType: "req",
	}
}
