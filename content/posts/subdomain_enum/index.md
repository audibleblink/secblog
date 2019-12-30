---
title: "Stop Using Python for Subdomain Enumeration"
description: "Oh, hello. I see you brought your pitchforks"
date: 2019-04-20T13:02:17-04:00
---

Python (and all other scripting languages) use the host system's name resolution APIs. 
Skip the bottleneck and craft the DNS packets manually.

<!--more-->

## Setup

**Tools Tested**:

* Subbrute - https://github.com/TheRook/subbrute
* Fernmelder - https://github.com/stealth/fernmelder
* Amass - https://github.com/OWASP/Amass

**Wordlist**: 

* [Seclists](https://github.com/danielmiessler/SecLists) - Discovery/DNS/subdomains-top1mil-110000.txt

**DNS Resolvers**:

```txt
4.2.2.1
1.1.1.1
8.8.8.8
64.6.64.6
77.88.8.8
74.82.42.42
4.2.2.2
1.0.0.1
8.8.4.4
4.2.2.3
9.9.9.10
64.6.65.6
77.88.8.1
4.2.2.4
```

## Results

_tests performed on WiFi. YMMV._

| Tool     | Command                                                           | Result                                            |
| ---      | ---                                                               | ---                                               |
| SubBrute | `./subbrute.py -s top110k.txt -r resolvers.txt example.com`       | `7.79s user 1.67s system 1% cpu 15:37.04 total`   |
| Amass    | `amass -d example.com -brute -w top110k.txt -noalts -norecursive` | `87.49s user 71.32s system 44% cpu 5:54.27 total` |
| Fernmelder | `awk '{print $1".example.com"}' top110k.txt \| fernmelder -4 -N 4.2.2.1 -N 1.1.1.1 -N 8.8.8.8 -N 64.6.64.6 -N 77.88.8.8 -N 74.82.42.42 -N 4.2.2.2 -N 1.0.0.1 -N 8.8.4.4 -N 4.2.2.3 -N 9.9.9.10 -N 64.6.65.6 -N 77.88.8.1 -N 4.2.2.4 -A` | `3.17s user 10.56s system 6% cpu 3:24.90 total ` |

##  Background
A few years ago I was introduced to a tool called Fernmelder for DNS subdomain enumeration. I'd
already been using tools like SubBrute and sublister for this purpose but my friend insisted I try
Fernmelder. It's a bit old school in the way it handles its inputs, as you can see from the chart
above. After trying it out, I was blown away and started using it exclusively. Enumerations that
typically lasted a few minutes were done in mere seconds. 

Why was it so much faster? Was it because Fernmelder is written in C? Well, probably, but it turns
out that Fernmelder manually crafts DNS queries and sends them straight down TCP socket
connections.  But still, why is this faster?

When an interpreted language requests an IP address for a hostname, this request gets passed up to
the runtime. The runtime interacts with the operating system, which in turn queries its
preconfigured DNS server. In Linux, the syscall responsible for doing this would be `glibc`'s 
[`gethostbyname`](http://man7.org/linux/man-pages/man3/gethostbyname.3.html).
It will do this for each hostname you're trying to enumerate. That ends up being a lot of overhead
when trying to blast through 3 million DNS requests.

Some other tools that also assist in enumerating subdomains are Amass and SubBrute. Many of these
subdomain enumeration tools do much more than just attempt to resolve names from a wordlist. Amass
is essentially a suite of host enumeration tools and as such would be a more viable tool for use by
a professional tester. For the purposes of this post, though, we're just looking at raw speed
regarding hostname resolution.

## "Analysis"

I'll compare the difference in implementation between Amass and SubBrute. (I don't know C well
enough to explain Fernmelder). Amass is similar to Fernmelder in that it manually creates the
DNS request packet.

Looking at the 
[relevant Amass source code](https://github.com/OWASP/Amass/blob/7c1b5cd946e5d97c802a3559b845e7debc1e2008/amass/resolvers.go#L599-L619)
, we can see the creation of the request packet in the `queryMessage` function.

```go
// https://github.com/OWASP/Amass/blob/7c1b5cd946e5d97c802a3559b845e7debc1e2008/amass/resolvers.go#L599-L619

func queryMessage(id uint16, name string, qtype uint16) *dns.Msg {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
			Id:                id,
			Rcode:             dns.RcodeSuccess,
		},
		Question: make([]dns.Question, 1),
	}
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(name),
		Qtype:  qtype,
		Qclass: uint16(dns.ClassINET),
	}
	m.Extra = append(m.Extra, setupOptions())
	return m
}
```

This function is called from a Resolver's private `writeMessage` function. See line 4 below.

```go
// https://github.com/OWASP/Amass/blob/7c1b5cd946e5d97c802a3559b845e7debc1e2008/amass/resolvers.go#L261-L275

func (r *resolver) writeMessage(co *dns.Conn, req *resolveRequest) {
	msg := queryMessage(r.getID(), req.Name, req.Qtype)

	co.SetWriteDeadline(time.Now().Add(r.WindowDuration))
	if err := co.WriteMsg(msg); err != nil {
		r.pullRequest(msg.MsgHdr.Id)
		estr := fmt.Sprintf("DNS error: Failed to write query msg: %v", err)
		r.returnRequest(req, makeResolveResult(nil, true, estr, 100))
		return
	}

	req.Timestamp = time.Now()
	r.queueRequest(msg.MsgHdr.Id, req)
	r.updatesAttempts()
}
```

Amass will then add this request to an in-memory queue where a separate goroutine processes the
job.


Compare this to SubBrute. Even though SubBrute can operate on multiple threads, it's still bound to
the eventual calling of the operating system's DNS query mechanism here:

`query = dnslib.DNSRecord.question(hostname, query_type.upper().strip())`

```python
# https://github.com/TheRook/subbrute/blob/master/subbrute.py#L53-L64
def query(self, hostname, query_type = 'ANY', name_server = False, use_tcp = False):
    ret = []
    response = None
    if name_server == False:
        name_server = self.get_ns()
    else:
        self.wildcards = {}
        self.failed_code = None
    self.last_resolver = name_server
    query = dnslib.DNSRecord.question(hostname, query_type.upper().strip())
    try:
        response_q = query.send(name_server, 53, use_tcp, timeout = 30)

```

## Conclusion

Fernmelder clocked in at 3.5 minutes. Next comes Amass at 6 minutes, and far behind is SubBrute.

Am I really all that concerned with saving 10 minutes on a task that is probably only run once
during a campaign? Should you be? Most certainly not, but I was curious enough at the discrepancy
in time and found the result interesting enough to share.

In regards to our third place test-case, this could really be any tool that relies on an OS API
call for name resolution. Perhaps in a future blog post I'll compare apples to apples and create a
python tool that manually crafts DNS request packets and sends them down a wire. That would be an
interesting test.

Overall, I'll probably move forward using Amass, given the plethora of other utilities available
within it. Despite my appreciation for Fernmelder's charming old-school interface of taking STDIN
and its speed, Amass, while not the fastest in this one specific task, seems the more viable
Professional's tool.
