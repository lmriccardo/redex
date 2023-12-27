# ReDEx - Remote Docker Execution Tool

> **WARNING**: EDUCATION PURPOSE ONLY

<video width="200" height="100" src="https://github.com/lmriccardo/redex/assets/32601287/3cf6e63a-5118-4697-b780-f845b709b9ae"></video>


When it comes to security, Docker by itself is a safe place to run potentially vulnerable applications, given the fact that all containers are isolated from each others and from the host system. However, Docker is a powerfull tool, and it provides to the user the capability to do everything he want either being safe or not. For example, we can *share* any portion of the host filesystem with the container using volumes or bind mounts. This means that it is possible to mount the entire host filesystem on the container just running `docker run -v /:/path`. Now, inside the container it is possible to alter the mounted filesystem without any restriction, but in particular it bypasses the namespace isolation, leaking a lot of information that an attacker can use to carry out an attack. 

**ReDEx** is tool that can remotely execute Docker commands via the Docker API on a remote host, which Docker Daemon has been exposed on (unsafe) TCP connections. Using actual HTTP (post, get, delete) requests it is possible to create, start, stop, inspect and list containers and images, and so on. However, all of these operations can also be used with malicious intent, in order to exploit the fact that the Daemon is exposed, creating privileged containers and performing so-called *Docker Breakout* techniques and *privilege escalation* on the host machine. 
