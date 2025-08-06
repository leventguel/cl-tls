	.section .bss
	.align 8
Result:
	.skip 32                 # Reserve 32 bytes
	
	.section .data

	.align 16
A_vec:
	.quad 0x66e94bd4ef8a2c3b, 0x884cfa59ca342b2e

	.align 16
B_vec:
	.quad 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF

hex_format:
	.asciz "Result: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n"

	.section .text
	.globl main
	.extern printf
	.extern gfmul

debug_format:
	.asciz "%%rdi points to: %p\n"
	
main:
	# Load input vectors
	movaps A_vec(%rip), %xmm0
	movaps B_vec(%rip), %xmm1

	lea Result(%rip), %rdi
	call gfmul

	lea debug_format(%rip), %rdi
	lea Result(%rip), %rsi
	mov $0, %rax
	call printf

	lea hex_format(%rip), %rdi     # format string
	lea Result(%rip), %r11         # pointer to buffer

	movzbq 0(%r11), %rax           # load byte
	mov %rax, %rsi                 # first argument

	movzbq 1(%r11), %rdx           # arg 2
	movzbq 2(%r11), %rcx           # arg 3
	movzbq 3(%r11), %r8            # arg 4
	movzbq 4(%r11), %r9            # arg 5

	subq $96, %rsp                  # align stack

	movzbq 5(%r11), %r10
	mov %r10, 0(%rsp)

	movzbq 6(%r11), %r10
	mov %r10, 8(%rsp)

	movzbq 7(%r11), %r10
	mov %r10, 16(%rsp)

	movzbq 8(%r11), %r10
	mov %r10, 24(%rsp)

	movzbq 9(%r11), %r10
	mov %r10, 32(%rsp)

	movzbq 10(%r11), %r10
	mov %r10, 40(%rsp)

	movzbq 11(%r11), %r10
	mov %r10, 48(%rsp)

	movzbq 12(%r11), %r10
	mov %r10, 56(%rsp)

	movzbq 13(%r11), %r10
	mov %r10, 64(%rsp)

	movzbq 14(%r11), %r10
	mov %r10, 72(%rsp)

	movzbq 15(%r11), %r10
	mov %r10, 80(%rsp)

	mov $0, %rax
	call printf

	addq $96, %rsp
	
	mov $0, %rdi   # exit code 0
	call exit
	
	.section .note.GNU-stack,"",@progbits
