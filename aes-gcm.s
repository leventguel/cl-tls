	.align 8
INS:
	.quad 0x1000000
	.align 16
ONE:
	.quad 0x1,0x0
	.align 16
TWO:
	.quad 0x2,0x0
	.align 16
THREE:
	.quad 0x3,0x0
	.align 16
FOUR:
	.quad 0x4,0x0
	.align 16
BSWAP_MASK:
	.byte 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
	.align 16
NEUTRAL_MASK:
	.byte 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	.align 16
BSWAP_EPI_64:
	.byte 7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	.align 16
LOAD_HIGH_BROADCAST_AND_BSWAP:
	.byte 15,14,13,12,11,10,9,8,15,14,13,12,11,10,9,8
	.globl AES_GCM_encrypt
AES_GCM_encrypt:
	# parameter 1: %rdi # *input
	# parameter 2: %rsi # *output
	# parameter 3: %rdx # *addt
	# parameter 4: %rcx # *ivec
	# parameter 5: %r8 # *tag
	# parameter 6: %r9 # nbytes
	# parameter 7: 128 + %rsp # abytes
	# parameter 8: 136 + %rsp # ibytes
	# parameter 9: 144 + %rsp # *key_schedule
	# parameter 10:152 + %rsp # nr
	pushq %rbp
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	pushq %rax
	pushq %rbx
	pushq %rcx
	pushq %rdx
	pushq %rsi
	pushq %rdi
	movq %rsp, %rbp
	andq $-64, %rbp
	sub $192, %rbp
HANDLE_IVEC:
	movq 136(%rsp), %rax
	cmp $12, %rax
	jne PROCESS_NON96BIT_IVEC
	jmp PROCESS_96BIT_IVEC
CALCULATE_POWERS_OF_H:
	movdqa (%rbp), %xmm1
	movdqa %xmm1, %xmm2
	call GFMUL
	movdqa %xmm1, 16(%rbp) # 16+rbp holds H^2
	call GFMUL
	movdqa %xmm1, 32(%rbp) # 32+rbp holds H^3
	call GFMUL
	movdqa %xmm1, 48(%rbp) # 48+rbp holds H^4
	pshufd $78, (%rbp), %xmm8
	pshufd $78, 16(%rbp), %xmm9
	pshufd $78, 32(%rbp), %xmm10
	pshufd $78, 48(%rbp), %xmm11
	pxor (%rbp), %xmm8
	pxor 16(%rbp), %xmm9
	pxor 32(%rbp), %xmm10
	pxor 48(%rbp), %xmm11
	movdqa %xmm8, 80(%rbp)
	movdqa %xmm9, 96(%rbp)
	movdqa %xmm10, 112(%rbp)
	movdqa %xmm11, 128(%rbp)
HANDLE_ADDT:
	pxor %xmm1, %xmm1
	movq 128(%rsp), %r10 # abytes
	movq %r10, %r11
	movq %r10, %r12
	shl $60, %r12
	shl $58, %r11
	shr $6, %r10
	je ADDT_SINGLES
ADDT_QUADS:
	#hash 4 blocks of header at a time
	movdqu (%rdx), %xmm8
	movdqu 16(%rdx), %xmm9
	movdqu 32(%rdx), %xmm10
	movdqu 48(%rdx), %xmm11
	add $64, %rdx
	dec %r10
	pshufb (BSWAP_MASK), %xmm8
	pshufb (BSWAP_MASK), %xmm9
	pshufb (BSWAP_MASK), %xmm10
	pshufb (BSWAP_MASK), %xmm11
	pxor %xmm1, %xmm8
	call REDUCE_FOUR
	jne ADDT_QUADS
ADDT_SINGLES: #hash remaining block
	shrq $62, %r11
	je ADDT_REMAINDER
	movdqu (%rbp), %xmm2
ADDT_SINGLES_LOOP:
	movdqu (%rdx), %xmm10
	add $16, %rdx
	dec %r11
	pshufb (BSWAP_MASK), %xmm10
	pxor %xmm10, %xmm1
	call GFMUL
	jne ADDT_SINGLES_LOOP
ADDT_REMAINDER:
	#hash the tail (partial block)
	shrq $60, %r12
	je HANDLE_DATA
	movdqu (%rbp), %xmm2
	movq (%rdx), %rax
	movq 8(%rdx), %rbx
	cmp $8, %r12
	jl ADDT_LESS_THEN_8
	jg ADDT_MORE_THEN_8
	xorq %rbx, %rbx
	jmp ADDT_REMAINDER_END
ADDT_LESS_THEN_8:
	movq $8, %rcx
	subq %r12, %rcx
	shlq $3, %rcx
	shlq %cl, %rax
	shrq %cl, %rax
	xorq %rbx, %rbx
	jmp ADDT_REMAINDER_END
ADDT_MORE_THEN_8:
	movq $16, %rcx
	subq %r12, %rcx
	shlq $3, %rcx
	shlq %cl, %rbx
	shrq %cl, %rbx
ADDT_REMAINDER_END:
	pinsrq $0, %rax, %xmm3
	pinsrq $1, %rbx, %xmm3
	pshufb (BSWAP_MASK), %xmm3
	pxor %xmm3, %xmm1
	call GFMUL
HANDLE_DATA:
	movq %r9, %r10
	movq %r9, %r11
	movq %r9, %r12
CALCULATE_COUNTERS:
	pshufb (BSWAP_MASK), %xmm0
	movdqa %xmm0, 64(%rbp)
	shl $60, %r12
	shl $58, %r11
	shr $6, %r10
	je DATA_SINGLES
DATA_FIRST_QUAD:
	movq 144(%rsp), %r15
	movq 152(%rsp), %r14
	movdqa %xmm0, %xmm8
	movdqa %xmm0, %xmm9
	movdqa %xmm0, %xmm10
	movdqa %xmm0, %xmm11
	paddd (ONE), %xmm8
	paddd (TWO), %xmm9
	paddd (THREE), %xmm10
	paddd (FOUR), %xmm11
	movdqa %xmm11, 64(%rbp)
	pshufb (BSWAP_MASK), %xmm8
	pshufb (BSWAP_MASK), %xmm9
	pshufb (BSWAP_MASK), %xmm10
	pshufb (BSWAP_MASK), %xmm11
	pxor (%r15), %xmm8
	pxor (%r15), %xmm9
	pxor (%r15), %xmm10
	pxor (%r15), %xmm11
ENC_FIRST_QUAD:
	cmpq $11, %r14
	movdqa 160(%r15), %xmm7
	aesenc 16(%r15), %xmm8
	aesenc 16(%r15), %xmm9
	aesenc 16(%r15), %xmm10
	aesenc 16(%r15), %xmm11
	aesenc 32(%r15), %xmm8
	aesenc 32(%r15), %xmm9
	aesenc 32(%r15), %xmm10
	aesenc 32(%r15), %xmm11
	aesenc 48(%r15), %xmm8
	aesenc 48(%r15), %xmm9
	aesenc 48(%r15), %xmm10
	aesenc 48(%r15), %xmm11
	aesenc 64(%r15), %xmm8
	aesenc 64(%r15), %xmm9
	aesenc 64(%r15), %xmm10
	aesenc 64(%r15), %xmm11
	aesenc 80(%r15), %xmm8
	aesenc 80(%r15), %xmm9
	aesenc 80(%r15), %xmm10
	aesenc 80(%r15), %xmm11
	aesenc 96(%r15), %xmm8
	aesenc 96(%r15), %xmm9
	aesenc 96(%r15), %xmm10
	aesenc 96(%r15), %xmm11
	aesenc 112(%r15), %xmm8
	aesenc 112(%r15), %xmm9
	aesenc 112(%r15), %xmm10
	aesenc 112(%r15), %xmm11
	aesenc 128(%r15), %xmm8
	aesenc 128(%r15), %xmm9
	aesenc 128(%r15), %xmm10
	aesenc 128(%r15), %xmm11
	aesenc 144(%r15), %xmm8
	aesenc 144(%r15), %xmm9
	aesenc 144(%r15), %xmm10
	aesenc 144(%r15), %xmm11
	jb FIRST_QUAD_LAST_ROUND
	cmpq $13, %r14
	movdqa 192(%r15), %xmm7
	aesenc 160(%r15), %xmm8
	aesenc 160(%r15), %xmm9
	aesenc 160(%r15), %xmm10
	aesenc 160(%r15), %xmm11
	aesenc 176(%r15), %xmm8
	aesenc 176(%r15), %xmm9
	aesenc 176(%r15), %xmm10
	aesenc 176(%r15), %xmm11
	jb FIRST_QUAD_LAST_ROUND
	movdqa 224(%r15), %xmm7
	aesenc 192(%r15), %xmm8
	aesenc 192(%r15), %xmm9
	aesenc 192(%r15), %xmm10
	aesenc 192(%r15), %xmm11
	aesenc 208(%r15), %xmm8
	aesenc 208(%r15), %xmm9
	aesenc 208(%r15), %xmm10
	aesenc 208(%r15), %xmm11
FIRST_QUAD_LAST_ROUND:
	aesenclast %xmm7, %xmm8
	aesenclast %xmm7, %xmm9
	aesenclast %xmm7, %xmm10
	aesenclast %xmm7, %xmm11
	pxor (%rdi), %xmm8
	pxor 16(%rdi), %xmm9
	pxor 32(%rdi), %xmm10
	pxor 48(%rdi), %xmm11
	movdqa %xmm8, (%rsi)
	movdqa %xmm9, 16(%rsi)
	movdqa %xmm10, 32(%rsi)
	movdqa %xmm11, 48(%rsi)
	add $64, %rsi
	add $64, %rdi
	dec %r10
	je FINAL_REDUCTION
	jmp DATA_QUADS
	.align 64
DATA_QUADS:
	movdqa (BSWAP_MASK), %xmm2
	movdqa %xmm8, %xmm0
	movdqa %xmm9, %xmm13
	movdqa %xmm10, %xmm14
	movdqa %xmm11, %xmm15
	movdqa 64(%rbp), %xmm8
	movdqa 64(%rbp), %xmm9
	movdqa 64(%rbp), %xmm10
	movdqa 64(%rbp), %xmm11
	pshufb %xmm2, %xmm0
	pshufb %xmm2, %xmm13
	pshufb %xmm2, %xmm14
	pshufb %xmm2, %xmm15
	pxor %xmm1, %xmm0
	movq 144(%rsp), %r15
	movq 152(%rsp), %r14
	paddd (ONE), %xmm8
	paddd (TWO), %xmm9
	paddd (THREE), %xmm10
	paddd (FOUR), %xmm11
	movdqa %xmm11, 64(%rbp)
	pshufb %xmm2, %xmm8
	pshufb %xmm2, %xmm9
	pshufb %xmm2, %xmm10
	pshufb %xmm2, %xmm11
	pxor (%r15), %xmm8
	pxor (%r15), %xmm9
	pxor (%r15), %xmm10
	pxor (%r15), %xmm11
	movdqa %xmm15, %xmm1
	pclmulqdq $0x00, (%rbp), %xmm1
	aesenc 16(%r15), %xmm8
	aesenc 16(%r15), %xmm9
	aesenc 16(%r15), %xmm10
	aesenc 16(%r15), %xmm11
	movdqa %xmm14, %xmm3
	pclmulqdq $0x00, 16(%rbp), %xmm3
	aesenc 32(%r15), %xmm8
	aesenc 32(%r15), %xmm9
	aesenc 32(%r15), %xmm10
	aesenc 32(%r15), %xmm11
	movdqa %xmm15, %xmm2
	pclmulqdq $0x11, (%rbp), %xmm2
	aesenc 48(%r15), %xmm8
	aesenc 48(%r15), %xmm9
	aesenc 48(%r15), %xmm10
	aesenc 48(%r15), %xmm11
	movdqa %xmm14, %xmm4
	pclmulqdq $0x11, 16(%rbp), %xmm4
	aesenc 64(%r15), %xmm8
	aesenc 64(%r15), %xmm9
	aesenc 64(%r15), %xmm10
	aesenc 64(%r15), %xmm11
	movdqa %xmm13, %xmm5
	pclmulqdq $0x00, 32(%rbp), %xmm5
	aesenc 80(%r15), %xmm8
	aesenc 80(%r15), %xmm9
	aesenc 80(%r15), %xmm10
	aesenc 80(%r15), %xmm11
	movdqa %xmm13, %xmm6
	pclmulqdq $0x11, 32(%rbp), %xmm6
	aesenc 96(%r15), %xmm8
	aesenc 96(%r15), %xmm9
	aesenc 96(%r15), %xmm10
	aesenc 96(%r15), %xmm11
	movdqa %xmm0, %xmm7
	pclmulqdq $0x00, 48(%rbp), %xmm7
	aesenc 112(%r15), %xmm8
	aesenc 112(%r15), %xmm9
	movdqa %xmm0, %xmm12
	pclmulqdq $0x11, 48(%rbp), %xmm12
	aesenc 112(%r15), %xmm10
	aesenc 112(%r15), %xmm11
	#holds xor of low products
	pxor %xmm3, %xmm1
	pxor %xmm7, %xmm5
	pxor %xmm5, %xmm1
	#holds xor of high products
	pxor %xmm4, %xmm2
	pxor %xmm12, %xmm6
	pxor %xmm6, %xmm2
	pshufd $78, %xmm15, %xmm3
	pshufd $78, %xmm14, %xmm4
	pshufd $78, %xmm13, %xmm5
	pshufd $78, %xmm0, %xmm6
	pxor %xmm15, %xmm3
	pxor %xmm14, %xmm4
	pxor %xmm13, %xmm5
	pxor %xmm0, %xmm6
	aesenc 128(%r15), %xmm8
	aesenc 128(%r15), %xmm9
	aesenc 128(%r15), %xmm10
	aesenc 128(%r15), %xmm11
	movdqa %xmm3, %xmm15
	pclmulqdq $0, 80(%rbp), %xmm15
	aesenc 144(%r15), %xmm8
	movdqa %xmm4, %xmm14
	pclmulqdq $0, 96(%rbp), %xmm14
	aesenc 144(%r15), %xmm9
	movdqa %xmm5, %xmm13
	pclmulqdq $0, 112(%rbp), %xmm13
	aesenc 144(%r15), %xmm10
	movdqa %xmm6, %xmm0
	pclmulqdq $0, 128(%rbp), %xmm0
	aesenc 144(%r15), %xmm11
	pxor %xmm15, %xmm14
	pxor %xmm13, %xmm0
	pxor %xmm1, %xmm14
	pxor %xmm2, %xmm0
	pxor %xmm14, %xmm0
	movdqa %xmm0, %xmm13
	psrldq $8, %xmm13
	pslldq $8, %xmm0
	pxor %xmm0, %xmm1
	pxor %xmm13, %xmm2
	movdqa %xmm1, %xmm4
	movdqa %xmm2, %xmm5
	movdqa %xmm1, %xmm3
	movdqa %xmm2, %xmm6
	psrld $31, %xmm4
	psrld $31, %xmm5
	pslld $1, %xmm3
	pslld $1, %xmm6
	movdqa %xmm4, %xmm1
	psrldq $12, %xmm1
	pslldq $4, %xmm4
	pslldq $4, %xmm5
	por %xmm4, %xmm3
	por %xmm5, %xmm6
	por %xmm1, %xmm6
	movdqa %xmm3, %xmm4
	movdqa %xmm3, %xmm5
	movdqa %xmm3, %xmm1
	pslld $31, %xmm4
	pslld $30, %xmm5
	pslld $25, %xmm1
	pxor %xmm5, %xmm4
	pxor %xmm1, %xmm4
	movdqa %xmm4, %xmm5
	psrldq $4, %xmm5
	pslldq $12, %xmm4
	pxor %xmm4, %xmm3
	pxor %xmm3, %xmm6
	movdqa %xmm3, %xmm1
	movdqa %xmm3, %xmm4
	psrld $1, %xmm1
	psrld $2, %xmm4
	psrld $7, %xmm3
	pxor %xmm6, %xmm4
	pxor %xmm3, %xmm1
	pxor %xmm4, %xmm1
	pxor %xmm5, %xmm1
	movdqa 160(%r15), %xmm7
	cmpq $11, %r14
	jb MESSAGE_ENC_LAST
	cmpq $13, %r14
	movdqa 192(%r15), %xmm7
	aesenc 160(%r15), %xmm8
	aesenc 160(%r15), %xmm9
	aesenc 160(%r15), %xmm10
	aesenc 160(%r15), %xmm11
	aesenc 176(%r15), %xmm8
	aesenc 176(%r15), %xmm9
	aesenc 176(%r15), %xmm10
	aesenc 176(%r15), %xmm11
	jb MESSAGE_ENC_LAST
	movdqa 224(%r15), %xmm7
	aesenc 192(%r15), %xmm8
	aesenc 192(%r15), %xmm9
	aesenc 192(%r15), %xmm10
	aesenc 192(%r15), %xmm11
	aesenc 208(%r15), %xmm8
	aesenc 208(%r15), %xmm9
	aesenc 208(%r15), %xmm10
	aesenc 208(%r15), %xmm11
MESSAGE_ENC_LAST:
	aesenclast %xmm7, %xmm8
	aesenclast %xmm7, %xmm9
	aesenclast %xmm7, %xmm10
	aesenclast %xmm7, %xmm11
	pxor (%rdi), %xmm8
	pxor 16(%rdi), %xmm9
	pxor 32(%rdi), %xmm10
	pxor 48(%rdi), %xmm11
	movdqa %xmm8, (%rsi)
	movdqa %xmm9, 16(%rsi)
	movdqa %xmm10, 32(%rsi)
	movdqa %xmm11, 48(%rsi)
	add $64, %rsi
	add $64, %rdi
	dec %r10
	jne DATA_QUADS
FINAL_REDUCTION:
	pshufb (BSWAP_MASK), %xmm8
	pshufb (BSWAP_MASK), %xmm9
	pshufb (BSWAP_MASK), %xmm10
	pshufb (BSWAP_MASK), %xmm11
	pxor %xmm1, %xmm8
	call REDUCE_FOUR
DATA_SINGLES:
	movdqa 64(%rbp), %xmm0
	shrq $62, %r11
	je DATA_REMAINDER
LOOP_DR:
	movq 144(%rsp), %r15
	movq 152(%rsp), %r14
	paddd (ONE), %xmm0
	movdqa %xmm0, %xmm10
	pshufb (BSWAP_MASK), %xmm10
	pxor (%r15), %xmm10
LOOP_DR1:
	addq $16, %r15
	dec %r14
	aesenc (%r15), %xmm10
	jne LOOP_DR1
	aesenclast 16(%r15), %xmm10
	pxor (%rdi), %xmm10
	movdqa %xmm10, (%rsi)
	addq $16, %rsi
	addq $16, %rdi
	dec %r11
	pshufb (BSWAP_MASK), %xmm10
	pxor %xmm10, %xmm1
	call GFMUL
	jne LOOP_DR
DATA_REMAINDER:
	shrq $60, %r12
	je DATA_END
	movq 144(%rsp), %r15
	movq 152(%rsp), %r14
	paddd (ONE), %xmm0
	pshufb (BSWAP_MASK), %xmm0
	pxor (%r15), %xmm0
LOOP_DR2:
	addq $16, %r15
	dec %r14
	aesenc (%r15), %xmm0
	jne LOOP_DR2
	aesenclast 16(%r15), %xmm0
	pxor (%rdi), %xmm0
	movdqa %xmm0, (%rsi)
	movq (%rsi), %rax
	movq 8(%rsi), %rbx
	cmp $8, %r12
	jl DATA_LESS_THEN_8
	jg DATA_MORE_THEN_8
	xorq %rbx, %rbx
	jmp DATA_REMAINDER_END
DATA_LESS_THEN_8:
	movq $8, %rcx
	subq %r12, %rcx
	shlq $3, %rcx
	shlq %cl, %rax
	shrq %cl, %rax
	xorq %rbx, %rbx
	jmp DATA_REMAINDER_END
DATA_MORE_THEN_8:
	movq $16, %rcx
	subq %r12, %rcx
	shlq $3, %rcx
	shlq %cl, %rbx
	shrq %cl, %rbx
DATA_REMAINDER_END:
	pinsrq $0, %rax, %xmm3
	pinsrq $1, %rbx, %xmm3
	pshufb (BSWAP_MASK), %xmm3
	pxor %xmm3, %xmm1
	call GFMUL
DATA_END:
	movq 128(%rsp), %r10
	shlq $3, %r9
	shlq $3, %r10
	pinsrq $0, %r9, %xmm3
	pinsrq $1, %r10, %xmm3
	pxor %xmm3, %xmm1
	movdqu (%rbp), %xmm2
	movdqu (%r8), %xmm10
	call GFMUL
	pshufb (BSWAP_MASK), %xmm1
	pxor %xmm1, %xmm10
	movdqu %xmm10, (%r8)
END:
	sub $0, %rsp
	popq %rdi
	popq %rsi
	popq %rdx
	popq %rcx
	popq %rbx
	popq %rax
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rbp
	ret
	###########################
PROCESS_96BIT_IVEC:
	movdqu (%rcx), %xmm0
	# xmm0 will hold the Y
	pinsrd $3, (INS), %xmm0
	movq 144(%rsp), %r15
	# key schedule
	movq 152(%rsp), %r12
	# number of rounds
	dec %r12
	movq %r12, 152(%rsp)
	movdqa (%r15), %xmm1
	# in xmm1 zero block is encrypted
	movdqa %xmm0, %xmm2
	pxor (%r15), %xmm2
	# in xmm2 Y is encrypted

LOOP_PI1: #parallelize aes encryption
	addq $16, %r15
	dec %r12
	aesenc (%r15), %xmm1
	aesenc (%r15), %xmm2
	jne LOOP_PI1
	aesenclast 16(%r15), %xmm1
	aesenclast 16(%r15), %xmm2
	pshufb (BSWAP_MASK), %xmm1
	# swap bytes
	movdqu %xmm2, (%r8)
	# store T at *tag
	movdqu %xmm1, (%rbp)
	# store H on stack

	jmp CALCULATE_POWERS_OF_H
	#############################
PROCESS_NON96BIT_IVEC:
	movq 144(%rsp), %r15
	# key schedule
	movq 152(%rsp), %r12
	# number of rounds
	movq 152(%rsp), %r12
	# number of rounds
	dec %r12
	movq %r12, 152(%rsp)
	movdqa (%r15), %xmm2
	# in xmm2 zero block is encrypted

LOOP_PNI1:
	addq $16, %r15
	dec %r12
	aesenc (%r15), %xmm2
	jne LOOP_PNI1
	aesenclast 16(%r15), %xmm2
	pshufb (BSWAP_MASK), %xmm2
	# swap bytes
	movdqu %xmm2, (%rbp)
	# store H on stack
	pxor %xmm1, %xmm1
	# Y is zero at first
	movq 136(%rsp), %r10 # ibytes
	movq %r10, %r11
	movq %r10, %r12
	xorq %r13, %r13
	shlq $3, %r12
	shlq $60, %r11
	shrq $4, %r10
	je PNI_REMAINDER

LOOP_PNI2: # hash ivec
	movdqu (%rcx), %xmm3
	add $16, %rcx
	dec %r10
	pshufb (BSWAP_MASK), %xmm3
	pxor %xmm3, %xmm1
	call GFMUL
	jne LOOP_PNI2
PNI_REMAINDER: # hash ivec remainder
	shrq $60, %r11
	je PNI_END
	movq (%rcx), %rax
	movq 8(%rcx), %rbx
	cmp $8, %r11
	jl PNI_LESS_THEN_8
	jg PNI_MORE_THEN_8
	xorq %rbx, %rbx
	jmp PNI_REMAINDER_END
PNI_LESS_THEN_8:
	movq $8, %rcx
	subq %r11, %rcx
	shlq $3, %rcx
	shlq %cl, %rax
	shrq %cl, %rax
	xorq %rbx, %rbx
	jmp PNI_REMAINDER_END

PNI_MORE_THEN_8:
	movq $16, %rcx
	subq %r11, %rcx
	shlq $3, %rcx
	shlq %cl, %rbx
	shrq %cl, %rbx
PNI_REMAINDER_END:
	pinsrq $0, %rax, %xmm3
	pinsrq $1, %rbx, %xmm3
	pshufb (BSWAP_MASK), %xmm3
	pxor %xmm3, %xmm1
	call GFMUL
PNI_END:
	pinsrq $0, %r12, %xmm3
	pinsrq $1, %r13, %xmm3
	pxor %xmm3, %xmm1
	call GFMUL
	pshufb (BSWAP_MASK), %xmm1
	movdqa %xmm1, %xmm0
	movq 144(%rsp), %r15
	# key schedule
	movq 152(%rsp), %r12
	# number of rounds
	pxor (%r15), %xmm1
LOOP_PNI3:
	addq $16, %r15
	dec %r12
	aesenc (%r15), %xmm1
	jne LOOP_PNI3
	aesenclast 16(%r15), %xmm1
	movdqu %xmm1, (%r8)
	# store T at *tag

	jmp CALCULATE_POWERS_OF_H
	##########################
	.align 16
REDUCE_FOUR:
	movdqa %xmm11, %xmm1
	movdqa %xmm11, %xmm2
	pclmulqdq $0x00, (%rbp), %xmm1
	pclmulqdq $0x11, (%rbp), %xmm2
	movdqa %xmm10, %xmm3
	movdqa %xmm10, %xmm4
	pclmulqdq $0x00, 16(%rbp), %xmm3
	pclmulqdq $0x11, 16(%rbp), %xmm4
	movdqa %xmm9, %xmm5
	movdqa %xmm9, %xmm6
	pclmulqdq $0x00, 32(%rbp), %xmm5
	pclmulqdq $0x11, 32(%rbp), %xmm6
	movdqa %xmm8, %xmm7
	movdqa %xmm8, %xmm12
	pclmulqdq $0x00, 48(%rbp), %xmm7
	pclmulqdq $0x11, 48(%rbp), %xmm12

	#holds xor of low products
	pxor %xmm3, %xmm1
	pxor %xmm7, %xmm5
	pxor %xmm5, %xmm1
	#holds xor of high products
	pxor %xmm4, %xmm2
	pxor %xmm12, %xmm6
	pxor %xmm6, %xmm2
	pshufd $78, %xmm11, %xmm3
	pshufd $78, %xmm10, %xmm4
	pshufd $78, %xmm9, %xmm5
	pshufd $78, %xmm8, %xmm6
	pxor %xmm11, %xmm3
	pxor %xmm10, %xmm4
	pxor %xmm9, %xmm5
	pxor %xmm8, %xmm6

	movdqa %xmm3, %xmm11
	pclmulqdq $0, 80(%rbp), %xmm11
	movdqa %xmm4, %xmm10
	pclmulqdq $0, 96(%rbp), %xmm10
	movdqa %xmm5, %xmm9
	pclmulqdq $0, 112(%rbp), %xmm9
	movdqa %xmm6, %xmm8
	pclmulqdq $0, 128(%rbp), %xmm8
	pxor %xmm11, %xmm10
	pxor %xmm9, %xmm8
	pxor %xmm1, %xmm10
	pxor %xmm2, %xmm8
	pxor %xmm10, %xmm8
	movdqa %xmm8, %xmm9
	psrldq $8, %xmm9
	pslldq $8, %xmm8
	pxor %xmm8, %xmm1
	pxor %xmm9, %xmm2
	movdqa %xmm1, %xmm4
	movdqa %xmm2, %xmm5
	psrld $31, %xmm4
	psrld $31, %xmm5
	movdqa %xmm1, %xmm3
	movdqa %xmm2, %xmm6
	pslld $1, %xmm3
	pslld $1, %xmm6
	#########################
	# a = xmm1
	# b = xmm2 - remains unchanged
	# res = xmm1
	# uses also xmm3,xmm4,xmm5,xmm6
GFMUL:
	movdqa %xmm1, %xmm3
	movdqa %xmm1, %xmm6
	pclmulqdq $0x00, %xmm2, %xmm3
	pclmulqdq $0x11, %xmm2, %xmm6
	pshufd $78, %xmm1, %xmm4
	pshufd $78, %xmm2, %xmm5
	pxor %xmm1, %xmm4
	pxor %xmm2, %xmm5
	##
	pclmulqdq $0x00, %xmm5, %xmm4
	pxor %xmm3, %xmm4
	pxor %xmm6, %xmm4
	movdqa %xmm4, %xmm5
	pslldq $8, %xmm5
	psrldq $8, %xmm4
	pxor %xmm5, %xmm3
	pxor %xmm4, %xmm6
	movdqa %xmm3, %xmm4
	movdqa %xmm6, %xmm5
	psrld $31, %xmm4
	psrld $31, %xmm5
	pslld $1, %xmm3
	pslld $1, %xmm6
	movdqa %xmm4, %xmm1
	psrldq $12, %xmm1
	pslldq $4, %xmm4
	pslldq $4, %xmm5
	por %xmm4, %xmm3
	por %xmm5, %xmm6
	por %xmm1, %xmm6
	movdqa %xmm3, %xmm4
	movdqa %xmm3, %xmm5
	movdqa %xmm3, %xmm1
	pslld $31, %xmm4
	pslld $30, %xmm5
	pslld $25, %xmm1
	pxor %xmm5, %xmm4
	pxor %xmm1, %xmm4
	movdqa %xmm4, %xmm5
	psrldq $4, %xmm5
	pslldq $12, %xmm4
	pxor %xmm4, %xmm3
	pxor %xmm3, %xmm6
	movdqa %xmm3, %xmm1
	movdqa %xmm3, %xmm4
	psrld $1, %xmm1
	psrld $2, %xmm4
	psrld $7, %xmm3
	pxor %xmm6, %xmm4
	pxor %xmm3, %xmm1
	pxor %xmm4, %xmm1
	pxor %xmm5, %xmm1
	ret
