	.globl gfmul
	.type gfmul, @function

gfmul:
	movb $0xAA, 0(%rdi)
	movb $0xBB, 1(%rdi)
	movb $0xCC, 2(%rdi)
	movb $0xDD, 3(%rdi)
	movb $0xEE, 4(%rdi)
	movb $0xFF, 5(%rdi)
	movb $0x11, 6(%rdi)
	movb $0x22, 7(%rdi)
	movb $0x33, 8(%rdi)
	movb $0x44, 9(%rdi)
	movb $0x55, 10(%rdi)
	movb $0x66, 11(%rdi)
	movb $0x77, 12(%rdi)
	movb $0x88, 13(%rdi)
	movb $0x99, 14(%rdi)
	movb $0x00, 15(%rdi)
	ret

	.section .note.GNU-stack,"",@progbits
