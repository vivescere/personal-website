---
title: "Writeup Cyber Threat Force : Flag checker"
date: 2021-07-09T00:01:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "reverse"]
type: "posts"
showDate: true
---

For this challenge, we were given a `program` executable.

```bash
$ ./program
./program FLAG

$ ./program MYFLAG
failed
```

Seems like it valides the flag that is passed as an argument. Let's open the binary in Ghidra.

There are a lot of functions defined, and looking at the exports we see that quite a lot of them start with `caml_`. I didn't know you could compile OCaml to C, that's pretty neat.

We can pinpoint the function that checks the flag by searching for strings. After looking for the event's flag format, `CYBERTF{...}`, we find a fake flag: `CYBERTF{Not-S0Easy-Fake-Flag}`. One function references it:

```c
undefined8 camlReverse__entry(void) {
  long lVar1;
  byte bVar2;
  long lVar3;
  
  camlReverse = &PTR_caml_curry2_00160098;
  DAT_00160150 = &PTR_caml_curry2_001600b8;
  DAT_00160158 = &PTR_caml_curry2_001600d8;
  DAT_00160160 = &PTR_camlReverse__char2int_207_001600f8;
  DAT_00160168 = &PTR_camlReverse__string2char_211_00160110;
  DAT_00160170 = &PTR_caml_curry2_00160128;
  DAT_00160178 = camlReverse__1;
  DAT_00160180 = &camlReverse__9;
  DAT_00160188 = &camlReverse__19;
  DAT_00160190 = &camlReverse__82;
  lVar3 = caml_c_call(1);
  if ((*(ulong *)(lVar3 + -8) >> 9 | 1) == 5) {
    lVar3 = caml_c_call(1);
    if (0x7ff < *(ulong *)(lVar3 + -8)) {
      camlReverse__string2char_211();
      camlReverse__char2int_207();
      lVar3 = camlReverse__firstCheck_268();
      if (lVar3 == 1) {
        camlStdlib__print_endline_361();
        return 1;
      }
      lVar3 = caml_c_call(1);
      if (0x7ff < *(ulong *)(lVar3 + -8)) {
        lVar1 = (*(ulong *)(*(long *)(lVar3 + 8) + -8) >> 10) * 8 + -1;
        bVar2 = *(byte *)(*(long *)(lVar3 + 8) + lVar1);
        lVar3 = caml_c_call(1);
        if (0x7ff < *(ulong *)(lVar3 + -8)) {
          camlStdlib__bytes__sub_115((lVar1 - (ulong)bVar2) * 2 + -0x13);
          camlStdlib__print_endline_361();
          camlReverse__string2char_211();
          camlReverse__char2int_207();
          camlReverse__xor_103();
          lVar3 = camlReverse__listequal_92();
          if (lVar3 != 1) {
            camlStdlib__print_endline_361();
            return 1;
          }
          camlStdlib__print_endline_361();
          camlStdlib__exit_459();
          return 1;
        }
      }
    }
  }
  else {
                    /* no args: print(sys.argv[0] + " FLAG") */
    lVar3 = caml_c_call(1);
    if (0x3ff < *(ulong *)(lVar3 + -8)) {
      camlStdlib__$5e_136();
      camlStdlib__print_endline_361();
      return 1;
    }
  }
                    /* WARNING: Subroutine does not return */
  caml_ml_array_bound_error();
}
```

We can understand the general flow from the functions names alone. First:

```c
// Convert the passed flag from a string to (probably custom using structs) char array.
camlReverse__string2char_211();

// Map each char to its int value.
camlReverse__char2int_207();

// Execute some kind of check on these integer values.
lVar3 = camlReverse__firstCheck_268();

// Exit here after printing an error message if the check failed.
if (lVar3 == 1) {
	camlStdlib__print_endline_361();
	return 1;
}
```

And then:

```c
// Subtract a value from some variable, probably shifting an array (the flag?).
camlStdlib__bytes__sub_115((lVar1 - (ulong)bVar2) * 2 + -0x13);

// Print something.
camlStdlib__print_endline_361();

// Convert the flag to a char array.
camlReverse__string2char_211();

// Once again, map each char to its int value.
camlReverse__char2int_207();

// XOR the flag.
camlReverse__xor_103();

// Compare it to some known value.
lVar3 = camlReverse__listequal_92();

// Exit here after printing an error message if the check failed.
if (lVar3 != 1) {
	camlStdlib__print_endline_361();
	return 1;
}

// And finally, print a message if we got the right flag.
camlStdlib__print_endline_361();
camlStdlib__exit_459();
```

Once again, let's take the easy route. We'll extract the flag using GDB, by looking at the check functions.

```bash
...
gef➤  disassemble camlReverse__firstCheck_268 
Dump of assembler code for function camlReverse__firstCheck_268:
   0x0000555555574100 <+0>:     sub    rsp,0x18
   0x0000555555574104 <+4>:     cmp    rax,0x1
   0x0000555555574108 <+8>:     je     0x555555574154 <camlReverse__firstCheck_268+84>
   0x000055555557410a <+10>:    cmp    rbx,0x1
   0x000055555557410e <+14>:    je     0x555555574148 <camlReverse__firstCheck_268+72>
   0x0000555555574110 <+16>:    mov    QWORD PTR [rsp],rbx
   0x0000555555574114 <+20>:    mov    QWORD PTR [rsp+0x8],rax
   0x0000555555574119 <+25>:    mov    rsi,QWORD PTR [rbx]
   0x000055555557411c <+28>:    mov    rdi,QWORD PTR [rax]
   0x000055555557411f <+31>:    lea    rax,[rip+0x11a2a]        # 0x555555585b50 <caml_equal>
   0x0000555555574126 <+38>:    call   0x55555559b81c <caml_c_call>
   0x000055555557412b <+43>:    mov    r15,QWORD PTR [r14]
   0x000055555557412e <+46>:    cmp    rax,0x1
   0x0000555555574132 <+50>:    je     0x555555574164 <camlReverse__firstCheck_268+100>
   0x0000555555574134 <+52>:    mov    rax,QWORD PTR [rsp]
   0x0000555555574138 <+56>:    mov    rbx,QWORD PTR [rax+0x8]
   0x000055555557413c <+60>:    mov    rax,QWORD PTR [rsp+0x8]
   0x0000555555574141 <+65>:    mov    rax,QWORD PTR [rax+0x8]
   0x0000555555574145 <+69>:    jmp    0x555555574104 <camlReverse__firstCheck_268+4>
   0x0000555555574147 <+71>:    nop
   0x0000555555574148 <+72>:    mov    eax,0x3
   0x000055555557414d <+77>:    add    rsp,0x18
   0x0000555555574151 <+81>:    ret    
   0x0000555555574152 <+82>:    xchg   ax,ax
   0x0000555555574154 <+84>:    cmp    rbx,0x1
   0x0000555555574158 <+88>:    je     0x555555574164 <camlReverse__firstCheck_268+100>
   0x000055555557415a <+90>:    mov    eax,0x1
   0x000055555557415f <+95>:    add    rsp,0x18
   0x0000555555574163 <+99>:    ret    
   0x0000555555574164 <+100>:   mov    eax,0x1
   0x0000555555574169 <+105>:   add    rsp,0x18
   0x000055555557416d <+109>:   ret    
End of assembler dump.
```

The function looks like a simple character check in a loop. Let's confirm this by looking at the parameters passed to `caml_c_call` (used to call `caml_equal`).

```bash
gef➤  b *0x0000555555574126
Breakpoint 1 at 0x555555574126

gef➤  r ABCDEFG

gef➤  p $rdi
$1 = 0x83

gef➤  p $rsi
$2 = 0x87
```

The values don't match. Let's run it again with the known flag format:

```bash
gef➤  r CYBERTF

gef➤  p $rdi
$1 = 0x87

gef➤  p $rsi
$2 = 0x87
```

The values match. Hitting `continue` brings us to the next comparison. Let's script this out:

```python
import string

alphabet = (
    '_' +
    string.ascii_lowercase +
    string.ascii_uppercase +
    string.digits +
    string.punctuation
)

found = ''
running = True

while running:
    for char in alphabet:
        # To avoid substitution errors, skip '.
        if char == "'":
            continue

        print(found + char)

        # Run the program.
        gdb.execute("r '" + found + char + "'")

        # Skip over the first N chars we already found.
        if len(found):
            gdb.execute('continue ' + str(len(found)))

        # Get the values of the registers.
        try:
            rdi = int(gdb.parse_and_eval("$rdi"))
            rsi = int(gdb.parse_and_eval("$rsi"))
        except:
            running = False
            break

        if rdi == rsi:
            found += char
            break
    else:
        break

print('=>', found)
```

```bash
gef➤  source extract_start.py
...
[Inferior 1 (process 1287983) exited normally]
=> CYBERTF{Go
```

After a few seconds, we get the start of the flag: `CYBERTF{Go`. Now let's look at the other function. We'll assume it checks the remaining part of the flag.

```bash
gef➤  disassemble camlReverse__listequal_92 
Dump of assembler code for function camlReverse__listequal_92:
   0x0000555555573e20 <+0>:     sub    rsp,0x18
   0x0000555555573e24 <+4>:     cmp    rax,0x1
   0x0000555555573e28 <+8>:     je     0x555555573e74 <camlReverse__listequal_92+84>
   0x0000555555573e2a <+10>:    cmp    rbx,0x1
   0x0000555555573e2e <+14>:    je     0x555555573e84 <camlReverse__listequal_92+100>
   0x0000555555573e30 <+16>:    mov    QWORD PTR [rsp],rbx
   0x0000555555573e34 <+20>:    mov    QWORD PTR [rsp+0x8],rax
   0x0000555555573e39 <+25>:    mov    rsi,QWORD PTR [rbx]
   0x0000555555573e3c <+28>:    mov    rdi,QWORD PTR [rax]
   0x0000555555573e3f <+31>:    lea    rax,[rip+0x11d0a]        # 0x555555585b50 <caml_equal>
   0x0000555555573e46 <+38>:    call   0x55555559b81c <caml_c_call>
   0x0000555555573e4b <+43>:    mov    r15,QWORD PTR [r14]
   0x0000555555573e4e <+46>:    cmp    rax,0x1
   0x0000555555573e52 <+50>:    je     0x555555573e68 <camlReverse__listequal_92+72>
   0x0000555555573e54 <+52>:    mov    rax,QWORD PTR [rsp]
   0x0000555555573e58 <+56>:    mov    rbx,QWORD PTR [rax+0x8]
   0x0000555555573e5c <+60>:    mov    rax,QWORD PTR [rsp+0x8]
   0x0000555555573e61 <+65>:    mov    rax,QWORD PTR [rax+0x8]
   0x0000555555573e65 <+69>:    jmp    0x555555573e24 <camlReverse__listequal_92+4>
   0x0000555555573e67 <+71>:    nop
   0x0000555555573e68 <+72>:    mov    eax,0x1
   0x0000555555573e6d <+77>:    add    rsp,0x18
   0x0000555555573e71 <+81>:    ret    
   0x0000555555573e72 <+82>:    xchg   ax,ax
   0x0000555555573e74 <+84>:    cmp    rbx,0x1
   0x0000555555573e78 <+88>:    jne    0x555555573e84 <camlReverse__listequal_92+100>
   0x0000555555573e7a <+90>:    mov    eax,0x3
   0x0000555555573e7f <+95>:    add    rsp,0x18
   0x0000555555573e83 <+99>:    ret    
   0x0000555555573e84 <+100>:   mov    eax,0x1
   0x0000555555573e89 <+105>:   add    rsp,0x18
   0x0000555555573e8d <+109>:   ret    
End of assembler dump.
```

We have the same pattern here, let's just quickly adapt the script.

```python
import string

alphabet = (
    '_' +
    string.ascii_lowercase +
    string.ascii_uppercase +
    string.digits +
    string.punctuation
)

found = 'CYBERTF{Go'
start_len = len(found)
running = True

while running:
    for char in alphabet:
        # To avoid substitution errors, skip '.
        if char == "'":
            continue

        print(found + char)

        # Run the program.
        gdb.execute("r '" + found + char + "'")

        # Skip over the first N chars we already found.
        if len(found) - start_len > 0:
            gdb.execute('continue ' + str(len(found) - start_len))

        # Get the values of the registers.
        try:
            rdi = int(gdb.parse_and_eval("$rdi"))
            rsi = int(gdb.parse_and_eval("$rsi"))
        except:
            running = False
            break

        if rdi == rsi:
            found += char
            break
    else:
        break

print('=>', found)
```

```bash
gef➤  # Remove the previous breakpoint first.
gef➤  del 1

gef➤  d *0x0000555555573e46
Breakpoint 2 at 0x555555573e46

gef➤  source extract_end.py
...
[Inferior 1 (process 1294818) exited normally]
=> CYBERTF{Golang_is_D3@d_1n_CTF_1795b4a89708371d16982195642638cd7783998188}
```

Here is the flag: `CYBERTF{Golang_is_D3@d_1n_CTF_1795b4a89708371d16982195642638cd7783998188}`.

It took around 4 minutes for it to finish.

## Additional notes

I've been wanting to learn about Ghidra's python API for a while now, so I decided after writing the post above to take a deeper look at how things are implemented, and to write a script that'll extract the flag.

Let's first check out `camlReverse__string2char_211`, by breaking right before it is called.

```bash
$ gdb ./program
gef➤  # Break right before camlReverse__string2char_211 is called.
gef➤  b *0x0000555555574278
gef➤  r ABCDEFG
gef➤  # The argument is loaded into rax, printing it reveals our flag (ABCDEFG).
gef➤  x/2x $rax
0x7ffff7c7ffa8: 0x44434241      0x00474645
gef➤  # Now let's run the function.
gef➤  stepi
gef➤  next
gef➤  next
gef➤  # When we're back into main, we see that the structure changed quite a bit.
gef➤  x/2x $rax
0x7ffff7c7fd30: 0x00000083      0x00000000
```

Looking at the function in Ghidra, it seems recursive:

```c
void camlReverse__string2char_211(void) {
  long in_RAX;
  
  camlReverse__string2char_tmp_214
            (1,*(undefined *)(in_RAX + (*(ulong *)(in_RAX + -8) >> 10) * 8 + -1));
  return;
}


long * camlReverse__string2char_tmp_214(long param_1) {
  long lVar1;
  long in_RAX;
  undefined8 uVar2;
  long unaff_RBX;
  long unaff_R14;
  long unaff_R15;
  
  if (param_1 == unaff_RBX) {
    return (long *)0x1;
  }
  uVar2 = camlReverse__string2char_tmp_214(param_1 + 2);
  if (unaff_R15 - 0x18U < *(ulong *)(unaff_R14 + 8)) {
    uVar2 = caml_call_gc();
  }
  *(undefined8 *)(unaff_R15 + -0x18) = 0x800;
  lVar1 = (*(ulong *)(in_RAX + -8) >> 10) * 8 + -1;
  if ((ulong)(param_1 >> 1) < lVar1 - (ulong)*(byte *)(in_RAX + lVar1)) {
    *(long *)(unaff_R15 + -0x10) = (ulong)*(byte *)(in_RAX + (param_1 >> 1)) * 2 + 1;
    *(undefined8 *)(unaff_R15 + -8) = uVar2;
    return (long *)(unaff_R15 + -0x10);
  }
                    /* WARNING: Subroutine does not return */
  caml_ml_array_bound_error();
}
```

The most interesting part is the `* 2 + 1` operation. Our `0x83` value really is `0x41 * 2 + 1`. If we show a bit more of the memory, we can find the other chars:

```bash
gef➤  x/64x $rax
0x7ffff7c7fd30: 0x00000083      0x00000000      0xf7c7fd48      0x00007fff
0x7ffff7c7fd40: 0x00000800      0x00000000      0x00000085      0x00000000
0x7ffff7c7fd50: 0xf7c7fd60      0x00007fff      0x00000800      0x00000000
0x7ffff7c7fd60: 0x00000087      0x00000000      0xf7c7fd78      0x00007fff
0x7ffff7c7fd70: 0x00000800      0x00000000      0x00000089      0x00000000
0x7ffff7c7fd80: 0xf7c7fd90      0x00007fff      0x00000800      0x00000000
0x7ffff7c7fd90: 0x0000008b      0x00000000      0xf7c7fda8      0x00007fff
0x7ffff7c7fda0: 0x00000800      0x00000000      0x0000008d      0x00000000
0x7ffff7c7fdb0: 0xf7c7fdc0      0x00007fff      0x00000800      0x00000000
0x7ffff7c7fdc0: 0x0000008f      0x00000000      0x00000001      0x00000000
0x7ffff7c7fdd0: 0x000004fc      0x00000000      0x00000000      0x07000000
0x7ffff7c7fde0: 0x00000400      0x00000000      0x555b8960      0x00005555
0x7ffff7c7fdf0: 0x000008f8      0x00000000      0x555b8b60      0x00005555
0x7ffff7c7fe00: 0x00000003      0x00000000      0x00000400      0x00000000
0x7ffff7c7fe10: 0x00000001      0x00000000      0x00000c00      0x00000000
0x7ffff7c7fe20: 0xf7c7fe40      0x00007fff      0x00000081      0x00000000
```

We have `0x83, 0x85, 0x87, ...`. This maps to our input, meaning we can get the start of the flag by decoding these values.

Also, we notice that each value has a pointer to the next one, meaning this is a linked list. We can build a first script to decode the start of the flag:

```python
import struct

def getUBytes(address, length):
  return bytearray([b & 0xff for b in getBytes(address, length)])

def u32(raw_bytes):
  return struct.unpack('<L', raw_bytes)[0]

def read_caml_array(pointer, data_len):
  array = []

  while True:
    try:
      array.append(getUBytes(toAddr(pointer), data_len))
    except:
      break

    pointer = u32(getBytes(toAddr(pointer + 8), 4))

  return array

# The address refers to the argument passed to camlReverse__firstCheck_268.
# For each value, map the bytes to an int, divide by two, and cast to char.
flag_start = b''.join(chr(u32(b) // 2) for b in read_caml_array(0x00160898, 4))

print(flag_start)
```
```python
extractCaml.py> Running...
CYBERTF{Go
extractCaml.py> Finished!
```

When reversing the `* 2 + 1` operation, all we really have to do is `// 2` (because it is an integer division).

We can now finish the job by extracting the XOR key & data, which are stored using the same array format:

```python
import struct
import itertools

def getUBytes(address, length):
  return bytearray([b & 0xff for b in getBytes(address, length)])

def u32(raw_bytes):
  return struct.unpack('<L', raw_bytes)[0]

def read_caml_array(pointer, data_len):
  array = []

  while True:
    try:
      array.append(getUBytes(toAddr(pointer), data_len))
    except:
      break

    pointer = u32(getBytes(toAddr(pointer + 8), 4))

  return array

# The address refers to the argument passed to camlReverse__firstCheck_268.
# For each value, map the bytes to an int, divide by two, and cast to char.
flag_start = b''.join(chr(u32(b) // 2) for b in read_caml_array(0x00160898, 4))

# The address refers to the argument passed to camlReverse__xor_103.
# For each value, map the bytes to an int.
xor_key = [u32(x) for x in read_caml_array(0x001601b0, 4)]

# The address refers to the argument passed to camlReverse__listequal_92.
# For each value, map the bytes to an int.
xor_data = [u32(x) for x in read_caml_array(0x00160208, 4)]

# Xor the key with the data, and divide each value by two before converting it to a char.
flag_end = ''.join(chr((a ^ b) // 2) for a, b in zip(itertools.cycle(xor_key), xor_data))

print(flag_start + flag_end)
```
```python
extractCaml.py> Running...
CYBERTF{Golang_is_D3@d_1n_CTF_1795b4a89708371d16982195642638cd7783998188}
extractCaml.py> Finished!
```

I have to say, the API doesn't seem too intuitive, but at least it is powerful.

## More

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/reverse/flag-checker) or [read other writeups](/blog/cyber-threat-force-ctf/).


