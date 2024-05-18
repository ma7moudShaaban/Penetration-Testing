# Scanning 
Firstly, it is essential to familiarize yourself with various network protocols such as TCP and UDP, with particular attention to the Three-Way Handshake process.
## Nmap
Nmap (Network Mapper) is a free and open-source utility designed for network discovery and security auditing.

1. # Host Scan 
 Host scan is used by penetration tester to identify active host in a network by sending ARP request packets to all system in that network. As result it will show a message “Host is up” by receiving MAC address from each active host. 


`nmap -Pn 192.168.1.1-225`
 
 
 * How it Works ? 
    Nmap uses the –Pn/-sn flag for host scan and broadcast ARP request packet to identify IP allocated to particular host machine.
    It will broadcast ARP request for a particular IP [suppose 192.168.1.100] in that network which can be the part of IP range [192.168.1.1-225] or CIDR [192.168.1.1/24 for class C] is used to indicate that we want to scan all the 256 IPs in our network. After then active host will unicast ARP packet by sending its MAC address as reply which gives a message Host is up.

2. # Port Scan
 If penetration testers want to identify open or close state of a particular port on target machine then they should go with nmap port scan.
Port Status: After scanning, you may see some results with a port status like filtered, open, closed, etc. Let me explain this.

• Open: This indicates that an application is listening for connections on this port.
• Closed: This indicates that the probes were received but there is no application listening on this port.
• Filtered: This indicates that the probes were not received and the state could not be established. It also indicates that the probes are being dropped by some kind of filtering.
• Unfiltered: During ACK Scan in order to detect firewall and means that the port is accessible, but it cannot be determined whether it is open or closed.
• Open/Filtered: This indicates that the port was filtered or open but Nmap couldn’t establish the state.
• Closed/Filtered: During Idle scan and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.

## Types of port scan 
It is important to note that Metasploit scanning modules may offer more accurate results when performing scans. Below are the different types of port scans and their corresponding Nmap commands:
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
        
            Ensure that the host remains idle during the scan to avoid interference.

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
3. # Service Scanning & Enumeration
- Scan using Nmap:
    - OS Detection Scan:
            `-O`
    - Version Scan:
            `-sV`
    - Aggressive Scan:
            this option enables additional advanced and aggressive options. Presently this enables OS detection (-O), version scanning (-sV), script scanning (-sC) and traceroute (–traceroute). This option only enables features, and not timing options (such as -T4) or verbosity options (-v) that you might want as well.
                `-A`
- Enumeration:

