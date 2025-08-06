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
	.quad 0x0000000000000000, 0x0000000000000000

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

	lea Result(%rip), %rdi   # Load address of Result into %rdi, pass pointer to gfmul

	# Call gfmul with Result buffer, gfmul writes to [rdi]
	call gfmul # Result is now in memory

	lea debug_format(%rip), %rdi
	lea Result(%rip), %rsi
	mov $0, %rax
	call printf
	
	# Save format string pointer
	lea hex_format(%rip), %rdi # format string → arg 1
	
	# Save Result pointer
	lea Result(%rip), %r12d

	movzbq 0(%r12d), %rax           # load byte
        mov %rax, %rsi                 # first argument
	
	# Load first 6 bytes into registers
	movzbl 1(%r12d), %edx     # byte 1 → arg 3
	movzbl 2(%r12d), %ecx     # byte 2 → arg 4
	movzbl 3(%r12d), %r8d     # byte 3 → arg 5
	movzbl 4(%r12d), %r9d     # byte 4 → arg 6

	# Allocate stack space: 16 bytes to maintain 16-byte alignment of stack  + 80 bytes for 10 ints
	# ints are 4 bytes on this arch but, the stack slots are 8 byte wide. so 10*8 not 10*4 here.
	# stack expects sizes of 8 on amd64 arch, it does not matter if we use movl (4 steps) or mov (8 steps) here
	# All stack-passed arguments in variadic functions are treated as if they were sizeof(long) or sizeof(double)
	# — i.e., 8 bytes.
	# Even for int, stack-passed args are treated as 8-byte slots
	# If you movl an int, it still occupies only 4 meaningful bytes, but the slot is 8 bytes wide.
	# The upper 4 bytes may be zero or garbage unless explicitly cleared
	# # Stack slots are 8 bytes wide on amd64, even for 4-byte types like int
	# Variadic functions treat all stack-passed arguments as 8-byte slots
	# This is not Windows-style shadow space — just alignment padding per System V ABI
	# you may use mov and r10 instead of movl and r10d here.
	
	subq $96, %rsp

	movzbl 5(%r12d), %r10d    # byte 5
	movl %r10d, 0(%rsp)       # put to stack

	movzbl 6(%r12d), %r10d
	movl %r10d, 8(%rsp)

	movzbl 7(%r12d), %r10d
	movl %r10d, 16(%rsp)

	movzbl 8(%r12d), %r10d
	movl %r10d, 24(%rsp)

	movzbl 9(%r12d), %r10d
	movl %r10d, 32(%rsp)

	movzbl 10(%r12d), %r10d
	movl %r10d, 40(%rsp)

	movzbl 11(%r12d), %r10d
	movl %r10d, 48(%rsp)

	movzbl 12(%r12d), %r10d
	movl %r10d, 56(%rsp)

	movzbl 13(%r12d), %r10d
	movl %r10d, 64(%rsp)

	movzbl 14(%r12d), %r10d
	movl %r10d, 72(%rsp)

	movzbl 15(%r12d), %r10d
	movl %r10d, 80(%rsp)
	
	mov $0, %rax              # no float args
	call printf

	# Clean up stack
	addq $96, %rsp

	ret

	.section .note.GNU-stack,"",@progbits
