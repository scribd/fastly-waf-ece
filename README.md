# Description

Fastly WAF events come in two flavors.  The first is a 'waf' event, which means something in an incoming request triggered an alarm.  You'll generally see one of these for every rule that was violated.

Fastly also sends a 'req' event, which has information about the request.  This will come out as soon as the request completes.

These two entry types will come in at different times, but must be correlated to truly make sense of what triggered the waf, and to really understand what should be done about it.

This Event Correlation Engine (ECE), is really just a syslog server that receives the log streams from Fastly, and holds them for a certain amount of time (the TTL) waiting for the rest of the entries for a given request to arrive.  Once the TTL expires, whatever is in memory is passed on, and the memory is flushed.

The default TTL is 20 seconds.

Correlated logs are written to STDERR and can be redirected as desired.

*NOTE:  This service is under development*

# Installation

        go get github.com/scribd/fastly-waf-ece

# Running

You can get help at any time by running:

    fastly-waf-ece help
    
Run on a given address:

    fastly-waf-ece -a 1.2.3.4:514
    
Run on a given address with a specific TTL:

    fastly-waf-ece -a 1.3.4.5:514 -t 30
    
Run in debug mode (dumps every log entry seen to STDOUT)

    fastly-waf-ece -a 1.2.3.4:514 -d


