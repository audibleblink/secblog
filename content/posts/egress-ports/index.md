+++
title = "Finding Your Way Out From Behind Firewalls with Strict Outbound Rules"
Description = "Finding Your Way Out From Behind Firewalls with Strict Outbound Rules"
date = "2017-02-07T19:44:18-05:00"
categories = ["HowTo"]
+++


You've achieved code execution on a machine, but for some reason your reverse shell isn't pinging you back.
Or that wget/tftp command isn't downloading your recon/post-exploitation tools. There's a chance you're
dealing with an egress problem. Typical ports that need outboud access are blocked. You try the main ones
you can think of (21, 22, 53, 80, 8080, 443), but none of them seem to be connecting. Do you start at 1 and
manually test? NO! The hallmarks of any decent programmer/hacker is laziness. So let's get lazy.

## The Concept

There's a few methods to achieve this, but at each of their cores, these 2 things are happening.

   * The attacking machine (66.66.66.66) needs to listen for something on every port.
   * Your victim machine (23.23.23.23.) needs to try to hit your machine on every port.


### netcat and iptables

__For the attacker__

Set all ports to redirect to a listener you've started.

~~~bash.prettyprint
iface=eth0
ip=66.66.66.66
lport=8080

iptables -t nat -A PREROUTING -i $iface -p tcp --dport 1:65535 -j DNAT --to-destination $ip:$lport
nc -nvlp $lport
~~~


__For the victim machine__

*nix: 

~~~bash.prettyprint
for port in (1..1000); do
  echo "Trying $port"
  nc -z -w1 66.66.66.66 $port
done
~~~

Netcat DOES accept ranges, so the following also works: `nc -w1 66.66.66.66 1-1000`. I usually find
that the bash loop's logging makes it easier to ID what worked if you walk away for a bit while it
runs.

### wireshark

If you have a GUI available on the attacking machine, you can repeat the above scenario, but
substitute the iptables and nc commands for wireshark with a sane filter; something like 

~~~bash.prettyprint
ip.src == 23.23.23.23
~~~

You should be able to watch the window for incoming packets and determine on which port
the victim machine was able to connect.

### egress-buster

If you've the ability to get files onto the target machine, the most robust option is
[egress-buster](https://github.com/trustedsec/egressbuster). The readme does a great job explaining
usage, but it's basically the first method, using iptables and python. It consists of two scripts,
a client and a server. It also has an option to automatically start the reverse shell once it finds
an available outgoing part.

