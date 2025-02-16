# Bourne Again Shell
- [Conditional Execution](#conditional-execution)



## Conditional Execution
- When defining various conditions, we specify which functions or sections of code should be executed for a specific value. If we reach a specific condition, only the code for that condition is executed, and the others are skipped. 

- Let us look at the first part of the script again and analyze it:
```bash
#!/bin/bash

# Check for given argument
if [ $# -eq 0 ]
then
	echo -e "You need to specify the target domain.\n"
	echo -e "Usage:"
	echo -e "\t$0 <domain>"
	exit 1
else
	domain=$1
fi

<SNIP>
```
- In summary, this code section works with the following components:

    - `#!/bin/bash` - Shebang.
    - `if-else-fi` - Conditional execution.
    - `echo` - Prints specific output.
    - `$# / $0 / $1` - Special variables.
    - `domain` - Variables.

- **Shebang**
    - The shebang line is always at the top of each script and always starts with "#!". This line contains the path to the specified interpreter (/bin/bash) with which the script is executed. We can also use Shebang to define other interpreters like Python, Perl, and others.
    ```python
    #!/usr/bin/env python
    ```
    ```perl
    #!/usr/bin/env perl
    ```

- **If-Else-Fi**
```bash
#!/bin/bash

value=$1

if [ $value -gt "10" ]
then
	echo "Given argument is greater than 10."
elif [ $value -lt "10" ]
then
	echo "Given argument is less than 10."
else
	echo "Given argument is not a number."
fi
```

- Execution: 
```bash
abdeonix@htb[/htb]$ bash if-elif-else.sh 5
Given argument is less than 10.


abdeonix@htb[/htb]$ bash if-elif-else.sh 12
Given argument is greater than 10.


abdeonix@htb[/htb]$ bash if-elif-else.sh HTB
if-elif-else.sh: line 5: [: HTB: integer expression expected
if-elif-else.sh: line 8: [: HTB: integer expression expected
Given argument is not a number.
```

- Several Conditions - Script.sh
```bash
#!/bin/bash

# Check for given argument
if [ $# -eq 0 ]
then
	echo -e "You need to specify the target domain.\n"
	echo -e "Usage:"
	echo -e "\t$0 <domain>"
	exit 1
elif [ $# -eq 1 ]
then
	domain=$1
else
	echo -e "Too many arguments given."
	exit 1
fi

<SNIP>
```

- Here we define another condition (`elif [<condition>];then`) that prints a line telling us (`echo -e "..."`) that we have given more than one argument and exits the program with an error (exit 1).

