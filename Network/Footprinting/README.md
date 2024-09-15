# FootPrinting
- [FTP](#ftp)
- [SMB](#smb)
- [NFS](#nfs)
- [DNS](#DNS)
- [SMTP](#smtp)
- [IMAP / POP3](#imap--pop3)
- [SNMP](#snmp)
- [MySQL](#mysql)
- [MSSQL](#mssql)
- [Oracle TNS](#oracle-tns)
- [IPMI](#ipmi)

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
- [ ] Check if the FTP server runs with TLS/SSL encryption.
- [ ] Nmap
    - [ ] Scanning TCP port 21 `sudo nmap -sV -p21 -sC -A TARGET_IP`
    - [ ] Scanning with Nmap Scripts `find / -type f -name ftp* 2>/dev/null | grep scripts`


> [!TIP]
> Trace the progress of NSE scripts at the network level if we use the `--script-trace` option


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

> [!TIP]
> Brute Forcing User RIDs
> `for i in $(seq 500 1100);do rpcclient -N -U "" TARGET_IP -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done`.
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


> [!TIP]
> Subdomain Brute forcing `for sub in $(cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @TARGET_IP | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done`. 
> Another tool work in the same way: `dnsenum --dnsserver TARGET_IP --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb`


- [ ] dig
    - [ ] `dig ns inlanefreight.htb @TARGET_IP`
    - [ ]  Query a DNS server's version `dig CH TXT version.bind TARGET_IP`
    - [ ] `dig any inlanefreight.htb @TARGET_IP`
    - [ ] `dig axfr inlanefreight.htb @TARGET_IP`

## SMTP
- SMTP is often combined with the IMAP or POP3 protocols.
- SMTP servers accept connection requests on `port 25`.Newer SMTP servers also use other ports such as `TCP port 587`.
- Default configuration file `/etc/postfix/main.cf`
- To interact with the SMTP server, we can use the telnet tool to initialize a TCP connection with the SMTP server.
- `telnet TARGET_IP 25`

- [ ] Nmap 
    - [ ] `sudo nmap TARGET_IP -sC -sV -p25` 
    - [ ] `sudo nmap TARGET_IP -p25 --script smtp-open-relay -v`

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
| 1 FETCH <ID> all          | Retrieves data associated with a message in the mailbox.                                          |
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
|rwuser noauth|	Provides access to the full OID tree without authentication.|
|rwcommunity <community string> <IPv4 address>|	Provides access to the full OID tree regardless of where the requests were sent from.|
|rwcommunity6 <community string> <IPv6 address>|	Same access as with rwcommunity with the difference of using IPv6.|

- We can use Onesixtyone can be used to brute-force the names of the community strings

- [ ] Onesixtyone
    - [ ] `onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt TARGET_IP`

> [!TIP]
> We can use [crunch](https://secf00tprint.github.io/blog/passwords/crunch/advanced/en) to create a custom wordlist.
> After we know community string, we can use braa tool to brute-force the individual OIDs and enumerate the information behind them: `braa <community string>@<IP>:.1.3.6.*   # Syntax`. e.g. `braa public@10.129.14.128:.1.3.6.*`

- [ ] snmpwalk
    - [ ] `snmpwalk -v2c -c public TARGET_IP`

## MySQL
- MySQL works according to the client-server principle and consists of a MySQL server and one or more MySQL clients.
- Configuration file `/etc/mysql/mysql.conf.d/mysqld.cnf`
- Usually, the MySQL server runs on TCP port 3306.

- **MySQL Commands**

|Command  | 	Description     |
|:--------|:--------------------|
|mysql -u <user> -p<password> -h <IP address>|	Connect to the MySQL server. There should not be a space between the '-p' flag, and the password.|
|show databases;|	Show all databases.|
|use <database>;|	Select one of the existing databases.|
|show tables;|	Show all available tables in the selected database.|
|show columns from <table>;|	Show all columns in the selected database.|
|select * from <table>;|	Show everything in the desired table.|
|select * from <table> where <column> = "<string>";|	Search for needed string in the desired table.|

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