	.section .data
R:              .quad 0xb32b6656a05b40b6, 0x952b2a56a5604ac0       # 128-bit operand R
S:              .quad 0xffcaff95f830f061, 0xdfa6bf4ded81db03       # 128-bit operand S
hex_chars:      .ascii "0123456789abcdef"                          # Lookup table for hex digits

msg_R:          .ascii "R = "                                      # Print label
msg_S:          .ascii "S = "
msg_Result:     .ascii "Result = "
newline:        .ascii "\n"

ascii_R:        .space 32                                          # Output buffer for hex string of R
ascii_S:        .space 32
ascii_Result:   .space 32

	.section .text
	.globl _start
	.align 16

_start:
	subq $64, %rsp              # Reserve 64 bytes on stack for workspace
	andq $-16, %rsp             # Align stack to 16 bytes

	movdqu R(%rip), %xmm1       # Load R into xmm1 (128-bit)
	movdqu S(%rip), %xmm2       # Load S into xmm2

	pxor %xmm0, %xmm0           # Clear xmm0, will store result Z

	movdqu %xmm1, 0(%rsp)       # Copy R to stack
	movdqu %xmm2, 16(%rsp)      # Copy S to stack

	movq $15, %rax              # Outer loop counter: 16 bytes of R

	.l01:
	movq $7, %r8                # Inner loop counter: 8 bits per byte

	.l0:
	movq (%rsp,%rax), %rbx      # Load current byte of R
	btq %r8, %rbx               # Test bit r8 in byte
	jnc .l1                     # If bit not set, skip xor

	movdqu 16(%rsp), %xmm3      # Load S from stack
	pxor %xmm3, %xmm0           # Z ^= S if bit in R is set

	.l1:
	movq 24(%rsp), %rbx         # Check MSB of S
	btq $0, %rbx
	jc .l2                      # If set, apply reduction

	# Shift S right by 1 (no reduction)
	shrq $1, 24(%rsp)
	shrq $1, 16(%rsp)
	movq 24(%rsp), %rbx
	shlq $63, %rbx              # Shift bit from upper to lower half
	orq %rbx, 16(%rsp)
	jmp .l3

	.l2:
	# Shift S and reduce using polynomial x^7 + x^2 + x + 1
	shrq $1, 24(%rsp)
	shrq $1, 16(%rsp)
	movq 24(%rsp), %rbx
	shlq $63, %rbx
	orq %rbx, 16(%rsp)
	xorb $0xe1, 31(%rsp)        # Apply reduction mask

	.l3:
	decq %r8                    # Next bit
	jns .l0

	decq %rax                   # Next byte
	jns .l01

	# Convert R to hex
	lea R(%rip), %rsi
	lea ascii_R(%rip), %rdi
	call convert_to_hex

	# Convert S to hex
	lea S(%rip), %rsi
	lea ascii_S(%rip), %rdi
	call convert_to_hex

	# Convert result Z to hex
	movdqu %xmm0, %xmm4
	movdqu %xmm4, 0(%rsp)
	lea 0(%rsp), %rsi
	lea ascii_Result(%rip), %rdi
	call convert_to_hex

	# Print R
	movq $1, %rax
	movq $1, %rdi
	lea msg_R(%rip), %rsi
	movq $4, %rdx
	syscall

	movq $1, %rax
	movq $1, %rdi
	lea ascii_R(%rip), %rsi
	movq $32, %rdx
	syscall

	movq $1, %rax
	movq $1, %rdi
	lea newline(%rip), %rsi
	movq $1, %rdx
	syscall

	# Print S
	movq $1, %rax
	movq $1, %rdi
	lea msg_S(%rip), %rsi
	movq $4, %rdx
	syscall

	movq $1, %rax
	movq $1, %rdi
	lea ascii_S(%rip), %rsi
	movq $32, %rdx
	syscall

	movq $1, %rax
	movq $1, %rdi
	lea newline(%rip), %rsi
	movq $1, %rdx
	syscall

	# Print Result
	movq $1, %rax
	movq $1, %rdi
	lea msg_Result(%rip), %rsi
	movq $9, %rdx
	syscall

	movq $1, %rax
	movq $1, %rdi
	lea ascii_Result(%rip), %rsi
	movq $32, %rdx
	syscall

	movq $1, %rax
	movq $1, %rdi
	lea newline(%rip), %rsi
	movq $1, %rdx
	syscall

	# Exit
	movq $60, %rax
	xor %rdi, %rdi
	addq $64, %rsp
	syscall

	# --------------------------------------------------
	# convert_to_hex: converts 16-byte buffer into 32 ASCII hex chars
	# Input: rsi = source pointer (16 bytes)
	#        rdi = destination pointer (32 ASCII chars)

convert_to_hex:
	xor %rcx, %rcx                 # Byte index
	.hex_loop:
	movzbl (%rsi,%rcx), %eax       # Load one byte
	mov %al, %bl
	shr $4, %bl                    # Get high nibble
	and $0x0F, %al                 # Get low nibble

	lea hex_chars(%rip), %r9
	movzbl (%r9,%rbx), %edx
	movb %dl, (%rdi,%rcx,2)        # First hex character

	movzbl (%r9,%rax), %edx
	movb %dl, 1(%rdi,%rcx,2)       # Second hex character

	inc %rcx
	cmp $16, %rcx
	jne .hex_loop
	ret
