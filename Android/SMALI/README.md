# SMALI
- [Introduction](#introduction)



## Introduction
![Reverse Flow](/images/ReversersFlow.jpg)
- Smali is the human readable version of Dalvik bytecode. Technically, Smali and baksmali are the name of the tools (assembler and disassembler, respectively), but in Android, we often use the term "Smali" refers to instructions.

- SMALI is like the assembly language: between the higher level source code and the bytecode.
- For the following Hello World Java code:
```java
public static void printHelloWorld() {
	System.out.println("Hello World")
}
The Smali code would be:
```
```smali
.method public static printHelloWorld()V
	.registers 2
	sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;
	const-string v1, "Hello World"
	invoke-virtual {v0,v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
	return-void
.end method
```
- The Smali instruction set is available [here](https://source.android.com/docs/core/runtime/dalvik-bytecode#instructions).
- To get the Smali from DEX, you can use the baksmali tool (disassembler) available [here](https://bitbucket.org/JesusFreke/smali/downloads/).The smali tool will allow you to assemble smali back to DEX.




