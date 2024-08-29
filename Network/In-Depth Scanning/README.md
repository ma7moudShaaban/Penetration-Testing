# In-Depth Scanning

- [Host Discovery & Port Scanning](#host-discovery--port-scanning)
    - [Port Scanning](#port-scanning)
    - [Types of Port Scanning](#types-of-port-scanning)
- [Service Enumeration](#service-enumeration)
    - [ ]


## Host Discovery & Port Scanning
- Discover running hosts in the network
```
sudo nmap 10.129.2.0/24 -sn -oA -PE tnet | grep for | cut -d" " -f5
sudo nmap -Pn 192.168.1.1-225 -oA tnet
```

- `-iL`: Performs defined scans against targets in provided 'hosts.lst' list.
- Disable the ICMP echo requests `-Pn`, Port scan `-sn`, DNS resolution `-n`, and ARP ping scan `--disable-arp-ping`
- `-oA` to save the results in all formats. 
- Convert xml output to html `xsltproc target.xml -o target.html`
- `--packet-trace`: Shows all packets sent and received.
- `--reason`: Displays the reason a port is in a particular state.	
### Port Scanning
- There are a total of 6 different states for a scanned port we can obtain:


| State     |                                    Description                                 |
|:----------------|:-------------------------------------------------------------------------|
| open            | This indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams as well as SCTP associations. |
| closed          | When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an RST flag. This scanning method can also be used to determine if our target is alive or not. |
| filtered        | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target. |
| unfiltered      | This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed. |
| open-filtered   | If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port. |
| closed-filtered | This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall. |


>[!NOTE]
> `-sT` TCP scan is default of scanning , `-sS` SYN scan is set only to default when we run it as root.

- `--top-ports=10`  get from the Nmap database that have been signed as most frequent.

#### Types of Port Scanning


- TCP Full Scan (Noisy):
            `-sT`
- Stealth Scan (Attempts to Bypass IPS or IDS):
            `-sS`
- ACK Scan (Detects firewall):
            `-sA`
- FIN Scan:
            `-sF`
- NULL Scan:
            `-sN`
- UDP Scan:
            `-sU`
- Xmas Scan:
            `-sX`
- Idle Scan (Uses a Zombie IP, Which Is an Idle Device with Low Traffic):
            `nmap -Pn -sI ZOMBIE_IP TARGET_IP` 
    There are steps to verify a suitable Zombie Host:
    1. Check for Incremental IP ID Sequence:
            The zombie host should use an incremental IP ID sequence. You can check this using Nmap:
                `nmap -Pn -p 80 --script ipidseq ZOMBIE_IP`
                The output will tell you if the IP ID sequence is incremental.
            . I recommend reviewing the ipidsec module in Metasploit for further analysis. You may find it beneficial to read more about this module to understand its capabilities fully.
    2. Confirm the Host Is Idle:
        - Ensure that the host remains idle during the scan to avoid interference.

- Decoy Scan:
            `-D IP,IP,IP,IP`
            `-D RND:5`
- Timing Template Scan:
            `-T`
                •  T0: paranoid
                •  T1: sneaky
                •  T2: polite 
                •  T3: normal
                •  T4: aggressive
                •  T5: insane
## Service Enumeration
- Scan using Nmap:
    - OS Detection Scan:
            `-O`
    - Version Scan:
            `-sV`
    - Aggressive Scan:
            this option enables additional advanced and aggressive options. Presently this enables OS detection (-O), version scanning (-sV), script scanning (-sC) and traceroute (–traceroute). This option only enables features, and not timing options (such as -T4) or verbosity options (-v) that you might want as well.
                `-A`

    - Default Script engines in Nmap: `-sC`




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




