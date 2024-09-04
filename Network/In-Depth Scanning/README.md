# In-Depth Scanning

- [Host Discovery & Port Scanning](#host-discovery--port-scanning)
    - [Port Scanning](#port-scanning)
    - [Types of Port Scanning](#types-of-port-scanning)
- [Service Enumeration](#service-enumeration)
- [Firewall and IDS/IPS Evasion](#firewall-and-idsips-evasion)


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

### Types of Port Scanning


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


## Firewall and IDS/IPS Evasion
- `-sA`: Perform ACK scan so when a port is closed or open, the host must respond with an RST flag.

- Decoy Scan:
            `-D IP,IP,IP,IP`
            `-D RND:5`

- `-S`: Scans the target by using different source IP address.
- `--dns-server`:  Specify DNS servers ourselves
- `--source-port`: Specify source port for our scans (e.g. TCP Port 53)
- **Connect to the filtered port**: `ncat -nv -p SOURCE_PORT TARGET_IP DEST_PORT`

