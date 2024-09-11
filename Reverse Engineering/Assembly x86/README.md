# Assembly x86
- [Assembly and Machine Code](#assembly-and-machine-code)
- [IA-32 Processor Architecture](#ia-32-processor-architecture)
- [History of IA-32 Architecture](#history-of-ia-32-architecture)
- [IA-32e x86 Memory Addresses](#ia-32e-x86-memory-addresses)
  - [Address Endianness](#address-endianness)


## Assembly and Machine Code

- When we compile a C program, the C compiler produces an assembly file. This assembly file is then converted into machine code with file extensions such as `.obj` or `.o`. Finally, during the linking phase, these object files are linked together to produce an executable (`.exe`) file, which the processor can run.

>[!NOTE]: Levels of Input-Output
>
>**Level 3**: High-level language function
>**Level 2**: Operating System
>**Level 1**: BIOS
>
>Assembly language programs can perform input-output at each of the above levels, plus **Level 0**: Hardware.
>Assembling (running MASM) does not actually create an executable program; additional steps are needed for linking.



- Assemble-Link Execute Cycle
  - If the source code is modified, Steps 2 through 4 must be repeated.
  ![Assemble-link execute cycle](../../images/assemble-link-execute-cycle.png "Assemble-link execute cycle")


- Instruction Set Architecture (ISA) mainly consists of the following components:

  - Instructions
  - Registers
  - Memory Addresses
  - Data Types

- There are two main Instruction Set Architectures that are widely used:

  - Complex Instruction Set Computer (CISC) - Used in Intel and AMD processors in most computers and servers.
  - Reduced Instruction Set Computer (RISC) - Used in ARM and Apple processors, in most smartphones, and some modern laptops.

- **CISC vs. RISC**
- The following table summarizes the main differences between CISC and RISC:

|Area  |	CISC	|   RISC |
|:----:|:-------:|:-------|
|Complexity|	Favors complex instructions|	Favors simple instructions|
|Length of instructions|	Longer instructions - Variable length 'multiples of 8-bits'|	Shorter instructions - Fixed length '32-bit/64-bit'|
|Total instructions per program	| Fewer total instructions - Shorter code	| More total instructions - Longer code|
|Optimization | 	Relies on hardware optimization (in CPU)	| Relies on software optimization (in Assembly)|
|Instruction Execution Time	| Variable - Multiple clock cycles	| Fixed - One clock cycle | 
|Instructions supported by CPU	| Many instructions (~1500)	| Fewer instructions (~200)|
|Power Consumption| 	High|	Very low|
|Examples|	Intel, AMD |	ARM, Apple|



## IA-32 Processor Architecture

### Basic Program Execution Registers

- Registers are high-speed storage locations directly inside the CPU.

### Types of Registers

1. **General Purpose Registers**
2. **Segment Registers**
3. **Processor Status Flags Register** (one register)
4. **Instruction Pointer**

1. General Purpose Registers

General-purpose registers are primarily used for arithmetic and data movement operations. The following image applies to EAX, EBX, ECX, and EDX:

![EAX register](../../images/EAX%20register.png "EAX")

### Index & Base Registers

The remaining general-purpose registers have only a 16-bit name for their lower half:

![Index & Base registers](../../images/Index%20&%20Base%20registers.png "Index & Base registers")

### Intended Register Use

#### General-purpose Registers

| Register | Use                  |
|----------|----------------------|
| EAX      | Accumulator          |
| ECX      | Loop Counter         |
| ESP      | Stack Pointer        |
| ESI, EDI | Index Registers      |
| EBP      | Extended (Stack) Frame (Base) Pointer |

2. Segment Registers

| Register | Use            |
|----------|----------------|
| CS       | Code Segment   |
| DS       | Data Segment   |
| SS       | Stack Segment  |

3. Processor Status Flags Register
- **EFlags**
  - Status and control flags.
  - Each flag is a single binary bit.

- Status Flags

  - **Carry**: Unsigned arithmetic out of range.
  - **Overflow**: Signed arithmetic out of range.
  - **Sign**: Result is negative.
  - **Zero**: Result is zero.


4. **EIP (Instruction Pointer)**
  - The address of the next instruction to be executed.

## History of IA-32 Architecture

1. **Intel 8086** - 16-bit Registers - RAM up to 1 MB
2. **Intel 80386** - 32-bit Registers - RAM up to 4 GB - Paging (Virtual Memory)
3. **Intel 80486** - Instruction Pipelining
4. **Pentium (P5)** - Superscalar (Multiple ALU)
5. **Intel 64 Mode** - 64-bit Linear Address Space
   - IA-32e Mode (2 Sub-Modes)
     - Compatibility mode for legacy 16 and 32-bit applications.
     - 64-bit mode uses 64-bit addresses and operands.

## IA-32e x86 Memory Addresses
- x86 64-bit processors have 64-bit wide addresses that range from 0x0 to 0xffffffffffffffff

|Addressing Mode|	Description	| Example |
|:--------------|:------------|:---------|
|Immediate|	The value is given within the instruction	|add 2|
|Register|	The register name that holds the value is given in the instruction	|add rax |
|Direct|	The direct full address is given in the instruction	| call 0xffffffffaa8a25ff|
|Indirect|	A reference pointer is given in the instruction	| call 0x44d000 or call [rax]|
|Stack|	Address is on top of the stack	|add rsp|

### Address Endianness 
- An address endianness is the order of its bytes in which they are stored or retrieved from memory. 
- There are two types of endianness: Little-Endian and Big-Endian
- With Little-Endian processors, the little-end byte of the address is filled/retrieved first right-to-left, while with Big-Endian processors, the big-end byte is filled/retrieved first left-to-right.





## Integers Constants

**[{+|-} digits (radix)]**

- Sign is optional
- Common radix characters:
  - h: hexadecimal
  - d: decimal
  - b: binary
- Note that hexadecimal can't begin with a letter: `0A5h`
- We can write expressions: `(2*3) + 4/6`

## Characters and Strings

- Enclosed in `''` or `""`
- Embedded quotes are allowed:
  - `'say "Good night," Grace'`

## Identifiers (Variables)

- 1-247 characters, including digits
- Not case sensitive
- First character must be a letter, `$`, `_`, `@`, or `?`

## Directives

- Instructions on how to assemble
- Used to declare code, data areas, and select memory model
- Not case sensitive (e.g., `.data`, `.DATA`)

### Defining Segments

- Data
- Code
- Stack `100h`

## Intel Instructions

### An Instruction Contains:

- Label (optional)
- Mnemonic (required)
- Operands (depend on the instruction)
- Comment (optional) - begins with `;`

Example:

```assembly
loop1: mov eax, 32 ; count of array elements
```

### NOP: No Operation Instruction

- Uses 1 byte of storage.
- Used to align code to even-address boundaries.

### Program Template

```assembly
TITLE ProjectName
.data

.code
main PROC
    ; We can use 'main' as a name for the main function or any other name such as 'abdeen'
    ; Insert executable instructions here
    exit
main ENDP
END main
```

Example:
```assembly
TITLE MyFirstProject
.code 
    main PROC
    mov eax, 10000h
    add eax, 40000h
    sub eax, 20000h
    call DumpRegs ; Print registers
    exit 
    main ENDP
END main
```

### Basic DataTypes
- BYTE, SBYTE: 8-bit Unsigned & Signed integers
- WORD, SWORD: 16-bit Unsigned & Signed integers
- DWORD, SWORD: 32-bit Unsigned & Signed integers
- QWORD: 64-bit integer | Not signed / unsigned 
- TBYTE: 80-bit (Ten byte) integer

### Define variable
e.g.
value1 BYTE 10
- use the ? symbol for undefined variable
#### Define Byte Array 
List1 BYTE 10,20,30,40


## x86 CPU Stack
- LIFO Structure
- Managed by the CPU, Using two registers
    - SS (Stack segment) - segment being used for stack
    - ESP (Stack pointer) - Pointer / Address / offset of top of stack 
- In Reality, the stack pointer starts at the highest location in the stack segment 
- During Pushing, The stack grows downward (into LOWER addresses/offsets)
- In Pop operation : Adds n to ESP, Where n is either 2 or 4 (depending on size of destination)


