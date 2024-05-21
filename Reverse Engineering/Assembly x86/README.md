# Assembly x86

## Assembly and Machine Code

- When we compile a C program, the C compiler produces an assembly file. This assembly file is then converted into machine code with file extensions such as `.obj` or `.o`. Finally, during the linking phase, these object files are linked together to produce an executable (`.exe`) file, which the processor can run.
- Note: Assembling (running MASM) does not actually create an executable program; additional steps are needed for linking.

## IA-32 Processor Architecture

### Basic Program Execution Registers

- Registers are high-speed storage locations directly inside the CPU.

### Types of Registers

- **General Purpose Registers**
- **Segment Registers**
- **Processor Status Flags Register** (one register)
- **Instruction Pointer**

### General Purpose Registers

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

#### Segment Registers

| Register | Use            |
|----------|----------------|
| CS       | Code Segment   |
| DS       | Data Segment   |
| SS       | Stack Segment  |

### Specialized Registers

- **EIP (Instruction Pointer)**
  - The address of the next instruction to be executed.
- **EFlags**
  - Status and control flags.
  - Each flag is a single binary bit.

### Status Flags

- **Carry**: Unsigned arithmetic out of range.
- **Overflow**: Signed arithmetic out of range.
- **Sign**: Result is negative.
- **Zero**: Result is zero.

## History of IA-32 Architecture

1. **Intel 8086** - 16-bit Registers - RAM up to 1 MB
2. **Intel 80386** - 32-bit Registers - RAM up to 4 GB - Paging (Virtual Memory)
3. **Intel 80486** - Instruction Pipelining
4. **Pentium (P5)** - Superscalar (Multiple ALU)
5. **Intel 64 Mode** - 64-bit Linear Address Space
   - IA-32e Mode (2 Sub-Modes)
     - Compatibility mode for legacy 16 and 32-bit applications.
     - 64-bit mode uses 64-bit addresses and operands.

## IA-32e x86 Memory Management

### Protected Mode

- Native mode for Windows and Linux.
- Processor prevents programs from referencing memory outside their assigned segments.

### Real-Address Mode

- Native mode for MS-DOS.
- Direct access to system memory and hardware devices, which can cause the OS to crash.

### System Management Mode

- Power management
- System security
- Diagnostics

## Addressable Memory

### Protected Mode

- Memory segment up to 4 GB
- 32-bit address

### Real-Address and Virtual-8086 Modes

- 1 MB space
- 20-bit address (segment-offset)

### Protected Mode Memory Models

- Flat segment model
- Multi-segment model
- Paging

## Levels of Input-Output

- **Level 3**: High-level language function
- **Level 2**: Operating System
- **Level 1**: BIOS
- Assembly language programs can perform input-output at each of the above levels, plus **Level 0**: Hardware

