# Bourne Again Shell
- [Conditional Execution](#conditional-execution)
- [Arguments, Variables, and Arrays](#arguments-variables-and-arrays)




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

## Arguments, Variables, and Arrays
- **Arguments**
    - The advantage of bash scripts is that we can always pass up to 9 arguments (`$0-$9`) to the script without assigning them to variables or setting the corresponding requirements for these.

    > [!NOTE]
    > 9 arguments because the first argument `$0` is reserved for the script.

    - As we can see here, we need the dollar sign (`$`) before the name of the variable to use it at the specified position. The assignment would look like this in comparison:
    
    ```bash
    [!bash!]$ ./script.sh ARG1 ARG2 ARG3 ... ARG9
    ASSIGNMENTS:       $0      $1   $2   $3 ...   $9
    ```

    - This means that we have automatically assigned the corresponding arguments to the predefined variables in this place.

    - These variables are called special variables. These special variables serve as placeholders. 

- **Special Variables**


    - IFS (Internal Field Separator) is a special variable in Bash that tells the shell how to split text when using commands like read or for loops.

    - By default, IFS is set to space, tab, and newline, meaning Bash splits text using these characters.

    - Special variables use the Internal Field Separator (IFS) to identify when an argument ends and the next begins. Bash provides various special variables that assist while scripting. Some of these variables are:

    |IFS|	Description|
    |:--:|:------------|
    |`$#`|	This variable holds the number of arguments passed to the script.|
    |`$@`|	This variable can be used to retrieve the list of command-line arguments.|
    |`$n`|	Each command-line argument can be selectively retrieved using its position. For example, the first argument is found at `$1`.|
    |`$$`|	The process ID of the currently executing process.|
    |`$?`|	The exit status of the script. This variable is useful to determine a command's success. The value 0 represents successful execution, while 1 is a result of a failure.|

> [!WARNING]
> After modifying IFS, reset it to avoid unexpected behavior.
> `IFS=$' \t\n'  # Default value (space, tab, newline)`

- **Variables**
    - The assignment of variables takes place without the dollar sign (`$`).
    - 