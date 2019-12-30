---
date: "2017-02-02T16:32:04-05:00"
title: "Configuring SSH for Pivoting"
Description: "How to leverage the SSH client's config file for pentesting"
Categories: [ "HowTo" ]
---

You're on a pentesting engagement and you've discovered a dual homed machine that allows you access to a subnet
you can't access directly from your attack machine. Assuming you've compromised at least one machine on the
initial network, you can use it as a proxy to other machines on the "hidden" subnet.

The ssh client has an often-overlooked configuration file that resides in your `~/.ssh` folder. You can
configure things in here that are specific to certain hosts or you can set default configurations for every
host. In order to access remote networks, wouldn't it be nice to shorten a command like:

~~~bash.prettyprint
ssh -l user -L 127.0.0.1:5432:132.31.321.123:5432 -p 20222 -i ~/.ssh/db/id_rsa remote.server.com
~~~

to something like:

~~~bash.prettyprint
ssh mount_psql
~~~

### SSH Config file

This file has a _lot_ of configuration options, but we're just going to focus on the one's that help us
pivot through 2+ networks.

__ControlMaster__

    Enables the sharing of multiple sessions over a single network connection. 
    When set to ''yes'', ssh(1) will listen for connections on a control socket 
    specified using the ControlPath argument. Additional sessions can connect 
    to this socket using the same ControlPath

__ControlPath__

    Specify the path to the control socket used for connection sharing as described 
    in the ControlMaster section above or the string ''none'' to disable connection 
    sharing

__ProxyCommand__

    Specifies the command to use to connect to the server. The command string extends 
    to the end of the line, and is executed with the user's shell. In the command 
    string, '%h' will be substituted by the host name to connect and '%p' by the port.

Ok, so the first two aren't strictly necessary for the pivoting, but subsequent connections to the same host
will just reuse the same authenticated socket, so it's lighting fast.

If you have the passwords for all the machines in your pivot chain, the client should ask you for each of
them, but the whole process is much smoother if you upload keys to each of them. The cool thing about the ssh
config file is that any program that uses ssh on the backend, can also use this file. So if you configure a
server entry called `skynet`...

~~~bash.prettyprint
ssh skynet
scp file.txt skynet:/tmp
rsync -avr skynet ...
ssh-copy-id -i ~/.ssh/id_rsa skynet
~~~

^ All of those work. 

So let's configure our `~/.ssh/config` file. Let's also assume root login is enabled on all the machines and
that we've already copied our ssh keys onto the remote machines.

~~~bash.prettyprint
ControlMaster auto
ControlPath /tmp/ssh_mux_%h_%p_%r
ServerAliveInterval 60 

Host first_hop
  Hostname 123.123.321.123
  User root
  IdentityFile ~/.ssh/id_rsa

Host second_hop
  Hostname 321.321.345.345
  User root
  IdentityFile ~/.ssh/id_rsa
  ProxyCommand ssh -w %h:%p first_hop

Host skynet
  Hostname 666.666.666.666
  User root
  IdentityFile ~/.ssh/id_rsa
  ProxyCommand ssh -w %h:%p second_hop
~~~

With this configuration, we're able to connect to `skynet`, which is 2 subnets removed from our current one,
with the command `ssh skynet`. Likewise, if we want to create a dynamic tunnel to allow for `proxychains`
usage, `ssh -fNTD 9050 skynet` should do the trick. Then `proxychains nmap...` to your hearts content!

The ProxyCommand directive in `skynet` is, in a way, declaring a prerequisite ssh connection to `second_hop`.
The `-w` flag states that the client should just go ahead and forward and STDIN/OUT through the next
connection.

That's it. Go forth and PIVAAAT!

![](https://az616578.vo.msecnd.net/files/2016/07/16/636042357012300047-1231186684_ross-pivot-friends.gif)

__Additional Resources:__

[SSH Client Configurations Docs](https://linux.die.net/man/5/ssh_config)
