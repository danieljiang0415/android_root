.global _start
.text

_start:

//-----load fd-----<-sp
//-----newsepolicy fd-----< --sp +4
//-----newsepolicy size ---<---sp+8
//-----map------<-sp+c
//

push {r0-r7, lr}

sub sp, sp, #16

//----------------open "/sys/fs/selinux/load"---------------
adr r0, selinux_load
mov r1, #2
mov r7, #5
svc 0
str r0, [sp]

//-----------------open "/data/local/tmp/sepolicy"---------------
adr r0, sepolicy
mov r1, #0
mov r7, #5
svc 0
str r0, [sp, #4]

// lseek to get size of file
ldr r0, [sp,#4]
mov r1, #0 // off 
mov r2, #2 // SEEK_END
mov r7, #19 // lseek
svc 0
str r0, [sp, #8]

// lseek back to beginning
ldr r0, [sp,#4]
mov r1, #0 // off
mov r2, #0 // SEEK_SET
mov r7, #19 // lseek
svc 0

// mmap
mov r0, #0
ldr r1, [sp, #8]
mov r2, #1 // PROT_READ
mov r3, #2 // MAP_PRIVATE
ldr r4, [sp, #4]
mov r5, #0
sub sp, sp, #8
str r4, [sp] // fd
str r5, [sp, #4]  // off
mov r7, #192 //mmap
svc 0
add sp, sp, #8
str r0, [sp, #12]

// write to the selinux load file
ldr r0, [sp]
ldr r1, [sp, #12]
ldr r2, [sp, #8]
mov r7, #4
svc 0

// unmap mem
ldr r0, [sp, #12]
ldr r1, [sp, #8]
mov r7, #91
svc 0

// close the files
ldr r0, [sp, #4]
mov r7, #6
svc 0

ldr r0, [sp]
mov r7, #6
svc 0

add sp, sp, #16
pop {r0-r7, lr}

//----goto org function
func_header:
	.int 0xe1a0c007		//copy from orgin functionn
b2fun_sec_op:
	.int 0xea000000	//------need to calc by developer


selinux_load:
	.ascii "/sys/fs/selinux/load\x0"
sepolicy:
	.ascii "/sepolicy\x0"
