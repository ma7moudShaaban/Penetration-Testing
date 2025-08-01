# SMALI
- [Introduction](#introduction)
- [Registers & Locals Directive](#registers--locals-directive)


## Introduction
![Reverse Flow](/images/ReversersFlow.jpg)
- Smali is the human readable version of Dalvik bytecode. Technically, Smali and baksmali are the name of the tools (assembler and disassembler, respectively), but in Android, we often use the term "Smali" refers to instructions.

- SMALI is like the assembly language: between the higher level source code and the bytecode.
- For the following Hello World Java code:
```java
public static void printHelloWorld() {
	System.out.println("Hello World")
}
```
- The Smali code would be:
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
- You can find dalvik-opcodes [here](http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html) that will help you get started with what a specific instruction does. 

## Registers & Locals Directive
- In Smali, registers are used to hold any type of value and are always 32 bits. To hold 64-bit values (long/double), two registers are used.  
- Each method/function has a declaration of the number of registers used in that method/function. 
- The `.registers` directive specifies the total number of registers used in the method, while the alternate `.locals` directive specifies the number of non-parameter registers used in the method. 
- Non-static methods include an extra hidden `this` → adds 1 parameter register
	- Example: A non-static method with 2 arguments = 3 parameter registers (this, arg1, arg2)
	```java
	public int multiply(int a, int b) {
		int result = a * b;
		return result;
	}
	```
	- It's non-static → `this`, `a`, `b` = 3 parameter registers
	- Local variable result = needs 1 local register
	- Total needed = 3 (params) + 1 (local) = 4 registers
	- Smali options:
	```smali
	.locals 1      ; 1 local + 3 params = 4 total
	```
	- OR
	```smali
	.registers 4   ; total registers (locals + params)
	```

- The below table depicts how data types of Java gets mapped into Smali: 

|Data Type 	|Smali Notation| 
|-----------|--------------|
|byte| 	B| 
|short| 	S| 
|int| 	I| 
|long| 	J| 
|float| 	F| 
|double| 	D| 
|boolean| 	Z| 
|char| 	C| 
|class or interface| 	Lclassname;| 

