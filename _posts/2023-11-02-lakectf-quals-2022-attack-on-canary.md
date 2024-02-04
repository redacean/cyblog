---
title: Attack on Canary - LakeCTF Quals 2022
categories: [ 2022 Writeups, LakeCTF Quals 2022 ]
tags: [ pwn, canary ]
---

Hello fellow hackers! Today we are solving the [Attack on Canary](https://github.com/polygl0ts/lakectf-2022) challenge from the [pwn](https://ctf.redacean.com/tags/pwn) category of [LakeCTF](https://lakectf.epfl.ch/) Quals 2022. This challenge consists in .

![LakeCTF Banner](/assets/img/lakectf.png)

## Getting Started

We are provided with an unstripped 64-bit ELF executable. One may guess from the challenge name and the security mechanisms in place that this challenge will likely consist in performing some attack on the stack canary. When running the program, we are asked to provide a command to _stdin_ and the program exits.

```terminal
$ file exe       
exe: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=2d9c8b5db536395e3203f9a943314354e19dbed5, not stripped

$ checksec --file exe       
[*] '/home/kali/ctf/2022/lakectf-2022/quals/pwn-attack-on-canary/remote_files/exe'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

$ ./exe 
Oof looks like this will be a bit more trouble...
Your command: d
```

## Reversing in Ghidra

Let's open the binary in [Ghidra](https://ghidra-sre.org/) and run the analysis with the default settings. The program is composed of three important functions:

1. `main()`, which simply calls `vulnerable()`,
2. `vulnerable()`, where the vulnerable code resides,
3. `win()`, which simply spawns a shell.

It now becomes clear we need to overwrite the return address of `vulnerable()` with the address of `win()` to get a shell and print the flag. Let's take a closer look at the `vulnerable()` function to understand how it may be exploited. The decompilation output by Ghidra is presented below.

```c
void vulnerable(void)

{
  long in_FS_OFFSET;
  int user_input;
  undefined array [88];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  while( true ) {
    while( true ) {
      fflush(stdin);
      printf("Your command: ");
      __isoc99_scanf(&DAT_00400a85,&user_input);
      if (user_input != 0) break;
      printf("Tell me which slot you wanna read: ");
      __isoc99_scanf(&DAT_00400ab4,&user_input);
      write(1,array + (user_input << 3),8);
    }
    if (user_input != 1) break;
    printf("Tell me how much you wanna write: ");
    __isoc99_scanf(&DAT_00400ab4,&user_input);
    printf("What are the contents (max 8 bytes): ");
    read(0,array,(long)user_input);
    puts("Good");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

The function defines two nested loops:

1. an inner loop that allows us to print a 8-byte chunk of data from the stack
2. an outer loop that allows us to write data to the stack

### Leaking the stack canary

Let's take a closer look at lines 13 to 18 of our decompilation:

```c
...
      printf("Your command: ");
      __isoc99_scanf(&DAT_00400a85,&user_input);
      if (user_input != 0) break;
      printf("Tell me which slot you wanna read: ");
      __isoc99_scanf(&DAT_00400ab4,&user_input);
      write(1,array + (user_input << 3),8);
...
```

- On line 3, we are asked to enter an integer.
- On line 4, if this integer is not 0, we break out of the inner loop.
- On line 6, we are asked to enter an integer again.
- On line 7, this value is shifted to the left by three bits and added to the address of the array defined on the stack. The 8-byte chunk located at the resulting address is printed to _stdout_.

Let's determine the value of the second integer we need to pass in to print the stack canary value.

![vulnerable() function stack](/assets/2023-11-06-lakectf-quals-2022-attack-on-canary/stack_vulnerable.png)
_vulnerable() function stack_

