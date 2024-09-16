# Remote Manangement Protocols
- [Linux Remote Management Protocols](#linux-remote-management-protocols)
    - [SSH](#ssh)
    - [Rsync](#rsync)
    - [R-Services](#r-services)
    

## Linux Remote Management Protocols
### SSH

- Default configuration file `/etc/ssh/sshd_config`
#### Dangerous Settings

|Setting	|      Description      |
|:-----------|:----------------------|
|PasswordAuthentication yes	|Allows password-based authentication.|
|PermitEmptyPasswords yes	|Allows the use of empty passwords.|
|PermitRootLogin yes	|Allows to log in as the root user.|
|Protocol 1	|Uses an outdated version of encryption.|
|X11Forwarding yes|	Allows X11 forwarding for GUI applications.|
|AllowTcpForwarding yes	|Allows forwarding of TCP ports.|
|PermitTunnel	|Allows tunneling.|
|DebianBanner yes	|Displays a specific banner when logging in.|

- Use SSH-Audit to footprint the service 
```
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py TARGET_IP
```

### Rsync
- Rsync is a fast and efficient tool for locally and remotely copying files. It can be used to copy files locally on a given machine and to/from remote hosts.
- It is often used for backups and mirroring.
- It uses port 873
- Probing for accessible shares `nc -nv 127.0.0.1 873`
- Enumerating an open share `rsync -av --list-only rsync://127.0.0.1/dev`
- We can sync all files to our attack host with the command `rsync -av rsync://127.0.0.1/dev`. If Rsync is configured to use SSH to transfer files, we can modify our commands to include the `-e ssh`flag, or `-e "ssh -p2222"` if a non-standard port is in use for SSH.
- [ ] Nmap 
    - [ ] `sudo nmap -sV -p 873 127.0.0.1`

### R-Services
- R-Services are a suite of services hosted to enable remote access or issue commands between Unix hosts over TCP/IP.
- It replaced by the Secure Shell (SSH) protocols.
- R-services span across the ports 512, 513, and 514.
- **The R-commands suite consists of the following programs:**

    - rcp (remote copy)
    - rexec (remote execution)
    - rlogin (remote login)
    - rsh (remote shell)
    - rstat
    - ruptime
    - rwho (remote who)

- Access using rlogin `rlogin 10.0.17.2 -l htb-student`
- The` /etc/hosts.equiv` file contains a list of trusted hosts and is used to grant access to other systems on the network.
-  The `hosts.equiv` and `.rhosts` files contain a list of hosts (IPs or Hostnames) and users that are trusted by the local host when a connection attempt is made using r-commands

- [ ] Nmap
    - [ ] `sudo nmap -sV -p 512,513,514 TARGET_IP`