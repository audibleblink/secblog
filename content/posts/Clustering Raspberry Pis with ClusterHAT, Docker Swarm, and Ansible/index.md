---
title: "Clustering Raspberry Pis With ClusterHAT, Docker Swarm, and Ansible"
date: 2021-10-08T11:25:41-04:00
draft: true
toc: true
images:
tags:
  - devops
  - homelab
---

It calls to you. 

Your drawer of misfit toys and abandoned projects.

It was to me, anyway. Every few months, I come back to world of SoCs to see what's new. Nothing
ever really sticks around long enough for it to be considered permamnent. 

- Smart mirrors
- [Twitter bots that shame you](https://twitter.com/thirstyplant1) for not watering
your plants
- Video Game emulators
- Home control devices
- The occasional GPIO project to manipulate things in MeatSpace

The only exception is probably an ad-blocking DNS server, the Pi-Hole. But even that's been
gradutaed to running as separate Linux Containers ([LXC](https://linuxcontainers.org)) spread
across hypervisors. 

All that said, this project is no different. But at least it was fun!

## The ClusterHAT

![](1.jpg)
> https://www.sparkfun.com/products/18155

The ClusterHAT sits atop a traditional Raspberry Pi, aka a HAT (Hardware Attached on Top). It also
has spots for you to insert 4 Raspberry Pi Zeros. When Gadget Mode is enabled, the Zeros will
attach to the HAT and are passed through to the main Pi. 

> Gadget Mode enables networking over USB

If comparing to a traditonal network setup, you may think of the HAT like a network switch.
When you combine the HAT with the modified Rasbian ISOs provided by [8086](https://www.8086.net),
in a couple of minutes you have a little cluser of Pis, ready to do your bidding. 

### Setup

The instruction over at https://clusterhat.com/setup-overview are pretty clear, but in summary:

- The main Pi has it's own ISO, which comes in two flavors:
  -   CNAT - Pi Zero are served IPs from the main Pi in the 172.19.181/24 range
  -   CBRIDGE - All 5 Pis are on the same network as you
- Pi Zeros get there own corresponding, numbered ISO
  - Pi #1 get ISO P1, and is assigned 172.18.181.1 when the main Pi is of the CNAT type
  - Pi #2 get ISO P2, and is assigned 172.18.181.2 
  - and so on

[You _may_ netboot](https://8086.support/index.php?action=faq&cat=23&id=97&artlang=en) 
all of the Zeros from the main Pi, but keep in mind you'd be sharing a single SDCard between 5
operating systems. It's cool to see, if you have the time, but it might not be an ideal long term
soultion. `apt upgrade` on 5 nodes took about an hour. YMMV since sdcards come in a variety of
speeds. 

[Netboot instructions here](https://8086.support/content/23/97/en/how-do-i-boot-pi-zeros-without-sd-cards-cluster-hat_cluster-ctrl.html)

Once all the sdcards are flashed, (or netboot shares copied), make sure to `touch /boot/ssh` on
each node to enable remote access.

On each Pi, run through the menu at `sudo raspi-config`. Spend as much or as little time as you
want here. I usually just go with:

![](2.png)

1. System Options
  - change password
  - change hostname
4. Performance Options
  - reduce gpu memory to 16
6. Advance Options
  - expand memory card
  

### Connecting to the Pis

First, if you haven't yet, make sure to supply power to the Zeros through the main Pi with:

```
clusterctrl up p{1,2,3,4}
```

Let's talk about the CNAT image. The Zeros arent directly accessible from the computer with which
you'll be using to connect to the cluster. We can simplify connecting to them by setting the main
Pi, which _is_ on your direct physical network, as a proxy jump.

In your ~/.ssh/config file, put in the following, with modifications for your hostnames and IPs, of
course:

```config
Host *.chappa.ai
  ProxyJump hammond
  User Pi

Host hammond.chappa.ai
    HostName 192.168.42.10

Host oneil.chappa.ai
    HostName 172.19.181.1

Host carter.chappa.ai
    HostName 172.19.181.2

Host tealc.chappa.ai
    HostName 172.19.181.3

Host danieljackson.chappa.ai
    HostName 172.19.181.4
```

You can then copy your ssh public key to each host with:

```bash
for name in {hammond,oneil,carter,tealc,danieljackson}.chappa.ai ; do
  ssh-copy-id -i ~/.ssh/id_ed25519 "${name}"
done
```

Enter your passwords and you should now be set up for passwordless ssh, which we'll need to
continue installing Docker on each node with Ansible.

## Docker Prep With Ansible

Rasberry Pis need to have some options enabled before containers are able to run. Their
`/boot/cmdline.txt` file needs to have appended the following:

```
cgroup_memory=1 cgroup_enable=memory cgroup_enable=cpuset
```

This tells the kernel to allow the use of `cgroups`, or "control groups". Docker containers are just
a scoped set of process and resources on your computer. Containers were around long before Docker,
Docker just made the use of Linux Namespaces and CGroups more accessible. 



### Small Tangent on Containers

> Containers are logical units of Linux kernel features, distributed as tarballs, whose processes
> are anchored to namespaces and controlled by CGroups.

#### Why are Namespaces

To create a Namespace for a process, additional flags must be passed to process-creation syscalls.
These additional flags can restrict what this process can see and what other processes can see
about it

**Things you can namespace**
- Hostname
- Process IDs
- Filesystems
- IPC
- Networking
- User IDs

#### Why are CGroups

At its most basic? They allow you to control, audit, and limit how your system's resources are
accessed or used.

**Resource limiting**
Groups can be set to not exceed a configured memory limit

**Prioritization**
Some groups may get a larger share of CPU or disk I/O

**Accounting**
Measures a group's resource usage

**Control**
Freezing groups of processes

What sorts of things can we control?

- Memory: `/sys/fs/cgroup/memory`
- CPU/Cores `/sys/fs/cgroup/cpu*`
- I/O `/sys/fs/cgroup/blkio`
- Processes `/sys/fs/cgroup/cgroup.procs`
- Devices `/sys/fs/cgroup/devices.*`


### Automating Setup

I've whipped up a GitHub repo with a simplified playbook and the more extensible folder structure.
https://github.com/audibleblink/clusterctrl-ansible/

First, we'll need to setup our inventory file and name our groups. Below is one possible
configuration.

```ini
# file: inventory.ini
[clusterctrl:children]
clusterctrl_server
clusterctrl_nodes

[clusterctrl_server]
hammond

[clusterctrl_nodes]
oneil
carter
tealc
danieljackson
```

If you'd like, create an `ansible.cfg` to save a couple keystrokes when calling `ansible-playbook`.
Otherwise you'd need to specify an inventory file each time.

```
[defaults]
inventory = ./inventory.ini
interpreter_python = /usr/bin/python3
```

The following task ensures, in an idempotent way, that our kernel flags exist on all our Pis, and
reboots the Pi if the flags weren't already there.

```yml
---

- name: Enable container features
  become: true
  register: containers_enabled
  replace:
    path: /boot/cmdline.txt
    regexp: '^([\w](?!.*\b{{ item }}\b).*)$'
    replace: '\1 {{ item }}'
  with_items:
  - "cgroup_enable=cpuset"
  - "cgroup_memory=1"
  - "cgroup_enable=memory"


- name: Reboot after enabling containers
  become: true
  when: containers_enabled.changed
  reboot:
```


Here we ensure all necessary packages, GPG keys, and repos are present before installing
`docker-ce`


```yml
---

- name: Install Docker Prereqs
  become: true
  apt:
    package: "{{ packages }}"
    state: present

- name: Add Docker GPG apt Key
  become: true
  apt_key:
    url: "{{ gpg_key_url }}"
    state: present
    keyring: "{{ gpg_key_out }}"

- name: Add Docker Repository
  become: true
  apt_repository:
    repo: "deb [arch={{arch}} signed-by={{ gpg_key_out }}] {{ repo_url }}  {{ release }} stable"
    state: present

- name: Update apt and install docker-ce
  become: true
  tags:
    - install
  apt:
    package: "{{ docker_packages }}"
    state: latest
    update_cache: yes
```

An example of a variable file that needs to exist for the code above to work looks like:

```yml

# docker prerequisites
packages:
  - apt-transport-https
  - ca-certificates
  - curl
  - gnupg
  - lsb-release

# docker repo gpg key location
gpg_key_url: https://download.docker.com/linux/raspbian/gpg

# outfile on local disk for docker repo gpg key
gpg_key_out: /usr/share/keyrings/docker-archive-keyring.gpg

# components for genreating the `deb` line being added to `/etc/apt/sources.list.d`
repo_url: https://download.docker.com/linux/raspbian
release: buster
arch: armhf

# installing docker
docker_packages:
  - docker-ce 
  - docker-ce-cli 
  - containerd.io
```

#### Folder Structure

All of the tasks can live in a single playbook, we don't need to over complicate things and use
the folder heirarchy the Ansible Docs recommend for managing big fleets.

...

But we're gonna anyways. Reminder that the simple, single-file is available here.
https://github.com/audibleblink/clusterctrl-ansible/simple

```
├── ansible.cfg
├── clusterctrl.yml
├── inventory.list
├── roles
│   ├── clusterctrl
│   │   ├── tasks
│   │   │   ├── main.yml
│   │   │   ├── apt_upgrade.yml
│   │   │   ├── ensure_aptitude.yml
│   │   │   ├── enable_containers.yml
│   │   │   ├── install_docker.yml
│   │   │   ├── docker_group_add.yml
│   │   │   └── swarm_init.yml
│   │   ├── vars
│   │   │   └── main.yml

```

> Why even talk about the folder structure then?

I wanted to share a complete and shareable process to setup all the Pis, but also one that's
modular.  Some may already have an ansible repo and probably already have playbooks to manage
updates, upgrades, and user management so it might not make sense to keep those tasks here and
could be removed. Sharing it in this form makes it a bit easier to incorporate.

If someone's just starting their Ansible repo, this could serve as a starting point. 

---

Once all Pis are up and playbooks intact, a simple

```sh
ansible-playbook clusterctrl.yml
```

should do the trick.


## Docker Swarm Init

Technically it's possible to both initialize and populate the Swarm with an Ansible playook/task as
well, but it requires some more setup and plugins. We'll meet in the middle though, and still use
ansible to run the commands remotely instead of ssh-ing to each. (although that is what's happening
in ansible's background anyway)


Because of our `inventory.list` file in the current directory, on the main Pi, we can run:

```bash
ansible clusterctrl_server -a "docker swarm init --advertise-addr 172.19.181.254"
```

That IP is for the internal network interface that the Pi Zeros can see, not the interface exposed to
your LAN

You'll get an output that that includes a line that looks like:

```
docker swarm join \
  --token SWMTKM-1-1y1rdnp7zjcj2vfw7mkhwzrwizqzixzffmoz4wew1brs0vlnh7-4axlaf1luquyxdgdq6gp3jalr \
  172.19.181.254:2377
```

Go ahead and run that command on each node.

```bash
❯❯ ansible clusterctrl_nodes -a "docker swarm join --token SWMTKM-1-1y1rdnp7zjcj2vfw7mkhwzrwizqzixzffmoz4wew1brs0vlnh7-4axlaf1luquyxdgdq6gp3jalr 172.19.181.254:2377"
```


Hopefull your our output looks like:

```bash
❯❯ ansible clusterctrl_nodes -a "docker swarm join --token SWMTKN-1-5lyx690gdzra3jw0ijeuug2sifezuohhb51sk6qw00n8dulebq-23l27nw3oxjh2591shgyncp39 172.19.181.254:2377"

carter | CHANGED | rc=0 >>
This node joined a swarm as a worker.
danieljackson | CHANGED | rc=0 >>
This node joined a swarm as a worker.
oneil | CHANGED | rc=0 >>
This node joined a swarm as a worker.
```

View your new Swarm Cluster with:
```
pi@hammond:~ $ docker node ls
ID                            HOSTNAME        STATUS    AVAILABILITY   MANAGER STATUS   ENGINE VERSION
o4i5q6yu4r3cc01t3nhcvv6nv *   hammond         Ready     Active         Leader           20.10.9
8f4k7jlwlfx60x0aadmjbn350     oneil           Ready     Active                          20.10.9
lpqd72inz9vooxgidyc14o7l6     carter          Ready     Active                          20.10.9
bhbwbtcyaw56oxzvb3hnawr5y     tealc           Ready     Active                          20.10.9
hxplragfdecau0x464s8jf5s9     danieljackson   Ready     Active                          20.10.9
```

## Deploying Our First Workload
