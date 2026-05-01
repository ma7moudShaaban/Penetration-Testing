# Attacking Common Applications
- [Joomla](#joomla)
    - [Enumeration](#enumeration)

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


## bruteforcing default password
sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

