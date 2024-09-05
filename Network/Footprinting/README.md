# FootPrinting
- [FTP](#ftp)
- [SMB](#smb)
- [NFS](#nfs)
- [DNS](#DNS)




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
- Smbclient allows us to execute local system commands using an exclamation mark at the beginning (!<cmd>)

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
>`for i in $(seq 500 1100);do rpcclient -N -U "" TARGET_IP -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done`.
> We can also use Python script from Impacket called [samrdump.py](https://github.com/fortra/impacket/blob/master/examples/samrdump.py).
> `samrdump.py TARGET_IP`

- Alternatives for RPCclient are [SMBmap](https://github.com/ShawnDEvans/smbmap) , [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) and [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) 

    - `smbmap -H TARGET_IP`
    - `crackmapexec smb TARGET_IP --shares -u '' -p ''`
    - `./enum4linux-ng.py TARGET_IP -A`



- [ ] Check for Null session 
- [ ] RPCclient
    - [ ] `rpcclient -U "" TARGET_IP`
- [ ] enum4linux-ng 
- [ ] Nmap
    - [ ] Scanning 139,445 ports `sudo nmap TARGET_IP -sV -sC -p139,445`
    - [ ] Scanning with Nmap Scripts `find / -type f -name smb* 2>/dev/null | grep scripts`




## NFS
- NFS has the same purpose as SMB. Its purpose is to access file systems over a network as if they were local.
- NFS is used between Linux and Unix systems.
- NFSv4 uses only one UDP or `TCP port 2049` to run the service.
- Default configuration file `/etc/exports`
- `insecure` option is dangerous because users can use ports above 1024. The first 1024 ports can only be used by root.

### **Dangerous Settings**

|Option|	Description        |
|:------|:---------------------|
|rw|	Read and write permissions.|
|insecure|	Ports above 1024 will be used.|
|nohide|	If another file system was mounted below an exported directory, this directory is exported by its own exports entry.|
|no_root_squash|	All files created by root are kept with the UID/GID 0.|



- [ ] Check available NFS shares `showmount -e TARGET_IP`
    - [ ] Mount availabe shares if found
    ```
    mkdir target-NFS
    sudo mount -t nfs TARGET_IP:/ ./target-NFS/ -o nolock
    ```
    - [ ] After we have done we can unmount the NFS share `sudo umount ./target-NFS`
- [ ] Nmap
    - [ ] `sudo nmap TARGET_IP -p111,2049 -sV -sC`
    - [ ] `sudo nmap --script nfs* TARGET_IP -sV -p111,2049`

## DNS 
- DNS servers work with three different types of configuration files:
    - local DNS configuration files
    - zone files
    - reverse name resolution files

- The DNS server Bind9 is very often used on Linux-based distributions. 
    -  Its local configuration file `/etc/bind/named.conf`
    -  The local configuration files are usually:
        - named.conf.local
        - named.conf.options
        - named.conf.log

### **Dangerous Settings**

|Option|	Description|
|:-------|:--------------|
|allow-query|	Defines which hosts are allowed to send requests to the DNS server.|
|allow-recursion|	Defines which hosts are allowed to send recursive requests to the DNS server.|
|allow-transfer|	Defines which hosts are allowed to receive zone transfers from the DNS server.|
|zone-statistics|	Collects statistical data of zones.|


>[!TIP]
>Subdomain Brute forcing `for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @TARGET_IP | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done`. 
>Another tool work in the same way: `dnsenum --dnsserver TARGET_IP --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb`


- [ ] dig
    - [ ] `dig ns inlanefreight.htb @TARGET_IP`
    - [ ]  Query a DNS server's version `dig CH TXT version.bind TARGET_IP`
    - [ ] `dig any inlanefreight.htb @TARGET_IP`
    - [ ] `dig axfr inlanefreight.htb @TARGET_IP`

