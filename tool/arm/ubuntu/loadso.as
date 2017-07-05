
.global _start

.text

_start:
    .code 32

    //-----save registers
    push   {r0-r7, lr}

    //-----check root
    mov    r12, r7
    mov    r7,  #0xC7
    svc    0
    mov    r7, r12
    cmp    r0, #0
    beq    dlopen
    b      orig_logic

    //-----load so
 dlopen:
    adr    r0, so
    mov    r1, #0
    ldr    r3, dlopen_off
    add    r3, pc, r3
    ldr    r3, [r3] // get dlopen from got
    blx    r3

    //--------restore registers--------
orig_logic:
    pop    {r0-r7, lr}

//-----------------------jmp to orig function header-------------    
org_opcode:
    .int 0             //the victim function header, first 4 bytes
	.int 0xea000000    //b victim function header + 4 , need to fix

dlopen_off:
    .int 0             //dlopen offset
so:
    .ascii "/system/lib/libvixl.so\x0"


/*
Disassembly of section .text:

00008000 <_start>:
    8000:   e92d40ff    push    {r0, r1, r2, r3, r4, r5, r6, r7, lr}
    8004:   e1a0c007    mov ip, r7
    8008:   e3a070c7    mov r7, #199    ; 0xc7
    800c:   ef000000    svc 0x00000000
    8010:   e1a0700c    mov r7, ip
    8014:   e3500000    cmp r0, #0
    8018:   0a000000    beq 8020 <dlopen>
    801c:   ea000005    b   8038 <orig_logic>

00008020 <dlopen>:
    8020:   e28f0020    add r0, pc, #32
    8024:   e3a01000    mov r1, #0
    8028:   e59f3014    ldr r3, [pc, #20]   ; 8044 <dlopen_off>
    802c:   e08f3003    add r3, pc, r3
    8030:   e5933000    ldr r3, [r3]
    8034:   e12fff33    blx r3

00008038 <orig_logic>:
    8038:   e8bd40ff    pop {r0, r1, r2, r3, r4, r5, r6, r7, lr}

0000803c <org_opcode>:
    803c:   00000000    .word   0x00000000
    8040:   ea000000    .word   0xea000000

00008044 <dlopen_off>:
    8044:   00000000    .word   0x00000000

00008048 <so>:
    8048:   7379732f    .word   0x7379732f
    804c:   2f6d6574    .word   0x2f6d6574
    8050:   2f6e6962    .word   0x2f6e6962
    8054:   00626461    .word   0x00626461
*/
