# Active Directory Enumeration & Attacks

- [Initial Enumeration](#initial-enumeration)
    - [External Recon](#external-recon)
    - [Enumeration of the Domain](#enumeration-of-the-domain)
        - [Identifying Hosts](#identifying-hosts)
        - [Identifying Users](#identifying-users)
- [Sniffing out a Foothold](#sniffing-out-a-foothold)
    - [LLMNR/NBT-NS Poisoning - from Linux](#llmnrnbt-ns-poisoning---from-linux)
        - [Responder](#responder)





## Initial Enumeration
### External Recon
- ASN / IP registrars: [arin](https://www.arin.net/) for searching the Americas, [RIPE](https://www.ripe.net/) for searching in Europe, [BGP Toolkit](https://bgp.he.net/)

- Domain Registrars & DNS: dig and [ICANN](https://lookup.icann.org/en) & [viewdns](https://viewdns.info/)

- Social Media	
- Cloud & Dev Storage Spaces: GitHub, [AWS S3 buckets](https://grayhatwarfare.com/) & Azure Blog storage containers [Azure Blog storage containers](https://grayhatwarfare.com/), Google searches using "Dorks" .

- Breach Data Sources: [HaveIBeenPwned](https://haveibeenpwned.com/) to determine if any corporate email accounts appear in public breach data, [Dehashed](https://www.dehashed.com/) to search for corporate emails with cleartext passwords or hashes we can try to crack offline. [TruffleHog](https://github.com/trufflesecurity/truffleHog)


### Enumeration of the Domain

- Key Data Points

|Data Point|	Description|
|:---------|:--------------|
|AD Users|	We are trying to enumerate valid user accounts we can target for password spraying.|
|AD Joined Computers|	Key Computers include Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers, etc.|
|Key Services|	Kerberos, NetBIOS, LDAP, DNS|
|Vulnerable Hosts and Services|	Anything that can be a quick win. ( a.k.a an easy host to exploit and gain a foothold)|

#### Identifying Hosts
- **Passive Scan**
    ```bash
    # On a host with GUI
    sudo -E wireshark
    ```
    - If we are on host without a GUI, We can use tcpdump or [netcreds](https://github.com/DanMcInerney/net-creds)
    ```bash
    sudo tcpdump -i ens224 
    ```

    - `pktmon.exe` (network monitoring tool built-in) was added to all editions of Windows 10.

    > [!NOTE]
    > As a note for testing, it's always a good idea to save the PCAP traffic you capture. You can review it again later to look for more hints, and it makes for great additional information to include while writing your reports.

    - **Responder**
        - Responder is a tool built to listen, analyze, and poison LLMNR, NBT-NS, and MDNS requests and responses.
    ```bash
    # Starting Responder
    sudo responder -I ens224 -A 
    ```

- **Active Scan**
    - Fping
        - [Fping](https://fping.org/) provides us with a similar capability as the standard ping application
        - Where fping shines is in its ability to issue ICMP packets against a list of multiple hosts at once and its scriptability
        - Also, it works in a round-robin fashion, querying hosts in a cyclical manner instead of waiting for multiple requests to a single host to return before moving on.

        ```bash
        # FPing Active Checks
        fping -asgq 172.16.5.0/23
        # a to show targets that are alive
        # s to print stats at the end of the scan 
        # g to generate a target list from the CIDR network 
        # q to not show per-target results.
        ```
    - Nmap
        - For our `hosts.txt` file, some of our results from Responder and fping overlapped
        ```bash
        sudo nmap -v -A -iL hosts.txt -oA /home/htb-student/Documents/host-enum
        ```

#### Identifying Users
- **[Kerbrute](https://github.com/ropnop/kerbrute) - Internal AD Username Enumeration**
    - It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts. 
    - We will use Kerbrute in conjunction with the jsmith.txt or jsmith2.txt user lists from [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames).
    ```bash
    # Cloning Kerbrute GitHub Repo
    sudo git clone https://github.com/ropnop/kerbrute.git

    # Compiling for Multiple Platforms and Architectures
    sudo make all

    # Testing the kerbrute_linux_amd64 Binary
    ./kerbrute_linux_amd64 

    # Adding the Tool to our Path
    echo $PATH

    # Moving the binary
    sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute

    # Enumerating Users with Kerbrute
    kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users

    
    ```

## Sniffing out a Foothold
### LLMNR/NBT-NS Poisoning - from Linux
- Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails.
- **LLMNR**
    - If a machine attempts to resolve a host but DNS resolution fails, typically, the machine will try to ask all other machines on the local network for the correct host address via LLMNR.
    - LLMNR is based upon the Domain Name System (DNS) format.
    - It uses port `5355` over UDP natively.
- **NBT-NS**
    - If LLMNR fails, the NBT-NS will be used.
    - NBT-NS identifies systems on a local network by their NetBIOS name. 
    - NBT-NS utilizes port `137` over UDP.

- Tools can be used to attempt LLMNR & NBT-NS poisoning: [Responder](https://github.com/lgandx/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh) and [Metasploit](https://www.metasploit.com/)


#### Responder 
- The use of the `-w` flag utilizes the built-in WPAD proxy server. 
- This can be highly effective, especially in large organizations, because it will capture all HTTP requests by any users that launch Internet Explorer if the browser has Auto-detect settings enabled.

```bash
# Starting Responder with Default Settings
sudo responder -I ens224 
```

- NetNTLMv2 hashes are very useful once cracked, but cannot be used for techniques such as pass-the-hash, meaning we have to attempt to crack them offline.

```bash
# Cracking an NTLMv2 Hash With Hashcat
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt 

```