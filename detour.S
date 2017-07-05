	.global _start

	.text
_start:

ldr r12, payload_location
bx r12

payload_location:
	.int 0
