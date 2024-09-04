# FootPrinting
- [FTP](#ftp)
- [SMB](#smb)





## FTP
- Control channel through `TCP port 21` and the data channel via `TCP port 20`.
- Trivial File Transfer Protocol (TFTP) is simpler than FTP.
    - It does not provide user authentication and other valuable features supported by FTP.
    - TFTP uses UDP.
    - TFTP does not have directory listing functionality.
- `vsFTPd` is one of the most used FTP servers on Linux-based distributions.
    - Default configuration file found in `/etc/vsftpd.conf`
    - Deny users access to the FTP service by this file`/etc/ftpusers`
    - Get overview of the server's settings `ftp> status`
    - If the `hide_ids=YES` setting is present, the UID and GUID representation of the service will be overwritten.
    - `ls_recurse_enable=YES` allows us to see all the visible content at once `ls -R`
    - Use `get` to Download files
    - Download all the files and folders we have access to at once:`wget -m --no-passive ftp://anonymous:anonymous@TARGET_IP` 
    - `PUT` command, we can upload files in the current folder to the FTP server.

- We can use other application to interact with ftp service:
```
nc -nv TARGET_IP 21
telnet TARGET_IP 21
```

- If the FTP server runs with TLS/SSL encryption, we can use the client openssl and communicate with the FTP server `openssl s_client -connect TARGET_IP:21 -starttls ftp`

- [ ] Check for Anonymous Login
- [ ] Check if we have the permissions to upload files to the FTP server
- [ ] Check if the FTP server runs with TLS/SSL encryption.
- [ ] Nmap
    - [ ] Scanning TCP port 21 `sudo nmap -sV -p21 -sC -A TARGET_IP`
    - [ ] Scanning with Nmap Scripts `find / -type f -name ftp* 2>/dev/null | grep scripts`


>[!TIP]
>Trace the progress of NSE scripts at the network level if we use the `--script-trace` option


## SMB 
- Samba: is a solution that enables the use of SMB in Linux and Unix distributions and thus cross-platform communication via SMB.
    - Samba implements the Common Internet File System (CIFS) network protocol.
    - When we pass SMB commands over Samba to an older NetBIOS service, it usually connects to the Samba server over `TCP ports 137, 138, 139`
    - CIFS uses `TCP port 445`
    - Default Configuration file `/etc/samba/smb.conf`
    - Connecting to the server's share with null session `smbclient -N -L //TARGET_IP`
    - Shares that ended with `$` are already included by default in the basic setting
    - We can see who, from which host, and which share the client is connected `sudo smbstatus`

### **Dangerous Settings**

|Setting|	Description      |
|:------|:------------------|
|browseable = yes|	Allow listing available shares in the current share?|
|read only = no|	Forbid the creation and modification of files?|
|writable = yes|	Allow users to create and modify files?|
|guest ok = yes|	Allow connecting to the service without using a password?|
|enable privileges = yes|	Honor privileges assigned to specific SID?|
|create mask = 0777|	What permissions must be assigned to the newly created files?|
|directory mask = 0777|	What permissions must be assigned to the newly created directories?|
|logon script = script.sh|	What script needs to be executed on the user's login?|
|magic script = script.sh|	Which script should be executed when the script gets closed?|
|magic output = script.out|	Where the output of the magic script needs to be stored?|


- Smbclient allows us to execute local system commands using an exclamation mark at the beginning (!<cmd>)
- **RPCclient**: is a tool to perform MS-RPC functions. RPCclient important functions:

|Query|	Description|
|:----|:-----------|
|srvinfo|	Server information.|
|enumdomains|	Enumerate all domains that are deployed in the network.|
|querydominfo|	Provides domain, server, and user information of deployed domains.|
|netshareenumall|	Enumerates all available shares.|
|netsharegetinfo <share>|	Provides information about a specific share.|
|enumdomusers|	Enumerates all domain users.|
|queryuser <RID>|	Provides information about a specific user.|

>[!TIP]
>Brute Forcing User RIDs
>`for i in $(seq 500 1100);do rpcclient -N -U "" TARGET_IP -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done`
> We can also use Python script from Impacket called [samrdump.py](https://github.com/fortra/impacket/blob/master/examples/samrdump.py).
> `samrdump.py TARGET_IP`

- Alternatives for RPCclient are [SMBmap](https://github.com/ShawnDEvans/smbmap) , [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) and [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) 

- `smbmap -H TARGET_IP`
- `crackmapexec smb TARGET_IP --shares -u '' -p ''`
- `./enum4linux-ng.py TARGET_IP -A`



- [ ] Check for Null session 
- [ ] RPCclient
    - [ ] `rpcclient -U "" TARGET_IP`
- [ ] Nmap
    - [ ] Scanning 139,445 ports `sudo nmap TARGET_IP -sV -sC -p139,445`
    - [ ] Scanning with Nmap Scripts `find / -type f -name smb* 2>/dev/null | grep scripts`

































- Enumeration:
1. NetBIOS:
* nbtscan: it is worth noting that nbtscan is also able to scan multiple  addresses.For example we can instruct the tool to scan all  the IP addresses in our target network 
                        `nbtscan 192.168.1.1/24`
2. SMB:
* Windows 2000 and higher allow us to run SMB directly over TCP/IP (direct hosting), without the need to run over NetBIOS sessions. To do this, the TCP port 445 is used. Since SMB provides several features such as manipulating files, sharing, messaging, Interprocess Communication (IPC), and more, it is one of the most attractive services to explore during our enumeration phase.
* enum4linux is a tool for enumerating information from Windows and Samba systems:
                        `enum4linux -a IP` 
* smbmap - smbclient - nmap smb script engines
3. SNMP:
* SNMP is based on UDP, a simple, stateless protocol.
         `snmp-check IP `
4. NFS: 
* Network File System. this is an RPC-based file sharing protocol often found configured on  Unix-like systems, is typically used to provide access to shared resources,  and can be found listening on TCP and/or UDP port 2049. Nmap can  easily identify a system running NFS.
* we can use the built-in `showmount` command with  the -e or --exports switches to show any exports that would be  available to us as well.
* nmap script engines > nfs-ls, nfs-showmount, nfs-statfs
5. SMTP: 
* nmap script engines > smtp-enum-users.nse, smtp-commands.nse, smtp-ntlm-info.nse
 
6. SSH: 
* Anonymous login, Hydra , paramiko script 




