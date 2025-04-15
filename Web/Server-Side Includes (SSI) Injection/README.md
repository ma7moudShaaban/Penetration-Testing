# Server-Side Includes (SSI) Injection
- SSI utilizes directives to add dynamically generated content to a static HTML page. 
- The use of SSI can often be inferred from the file extension. Typical file extensions include `.shtml`, `.shtm`, and `.stm`
- These directives consist of the following components:

    - name: the directive's name
    - parameter name: one or more parameters
    - value: one or more parameter values
- An SSI directive has the following syntax:

```ssi
<!--#name param1="value1" param2="value" -->
```

- exec: This directive executes the command given in the cmd parameter:

```ssi
<!--#exec cmd="whoami" -->
```
- include: This directive includes the file specified in the virtual parameter. It only allows for the inclusion of files in the web root directory.
```ssi
<!--#include virtual="index.html" -->
```

