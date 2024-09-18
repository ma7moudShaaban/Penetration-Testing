# Remote Manangement Protocols
- [Linux Remote Management Protocols](#linux-remote-management-protocols)
    - [SSH](#ssh)
    - [Rsync](#rsync)
    - [R-Services](#r-services)
- [Windows Remote Management Protocols](#windows-remote-management-protocols)
    - [RDP](#rdp)
    - [WinRM](#winrm)
    - [WMI](#wmi)
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

## Windows Remote Management Protocols
- Windows servers can be managed locally using Server Manager administration tasks on remote servers. 
- Remote management is enabled by default starting with Windows Server 2016. 
- The main components used for remote management of Windows and Windows servers are the following:

    - Remote Desktop Protocol (RDP)
    - Windows Remote Management (WinRM)
    - Windows Management Instrumentation (WMI)

### RDP 
- RDP uses TCP port 3389
- [Perl script](https://github.com/CiscoCXSecurity/rdp-sec-check) can unauthentically identify the security settings of RDP servers based on the handshakes. `./rdp-sec-check.pl TARGET_IP`
- To initiate an RDP session `xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:TARGET_IP`
- [ ] Nmap
    - [ ] `nmap -sV -sC TARGET_IP -p3389 --script rdp*`

### WinRM
- WinRM uses the Simple Object Access Protocol (SOAP) to establish connections to remote hosts and their applications. 
- WinRM must be explicitly enabled and configured starting with Windows 10.
- WinRM relies on TCP ports 5985 and 5986 for communication, with the last port 5986 using HTTPS
- Use [evil-winrm](https://github.com/Hackplayers/evil-winrm) to interact with this WinRM: `evil-winrm -i TARGET_IP -u USER -p PASS`

- [ ] Nmap
    - [ ] `nmap -sV -sC TARGET_IP -p5985,5986 --disable-arp-ping -n`

### WMI
- Windows Management Instrumentation (WMI) is Microsoft's implementation and also an extension of the Common Information Model (CIM), core functionality of the standardized Web-Based Enterprise Management (WBEM) for the Windows platform.
- WMI allows read and write access to almost all settings on Windows systems.
- WMI is typically accessed via PowerShell, VBScript, or the Windows Management Instrumentation Console (WMIC).
- WMI is not a single program but consists of several programs and various databases, also known as repositories.
- The initialization of the WMI communication always takes place on TCP port 135, and after the successful establishment of the connection, the communication is moved to a random port.
- The program [wmiexec.py](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py) from the Impacket toolkit can be used for this: `/usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@TARGET_IP "hostname"`
