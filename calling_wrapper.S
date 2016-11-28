/* 	This file implements the wrapper code for every calling convension.
	The function wrapper_start should save the location of itself to the global variable "wrapper_curfunc".
	the entire function will be copied from wrapper_start to wrapper_end for every KPlugs function - so it needs to be location independent */

#if defined(CONFIG_X86_64)

#define WORD        .quad
#define WORD_SIZE   8
#define AX          %rax
#define BX          %rbx
#define CX          %rcx
#define SP          %rsp
#define CODETYPE    .code64

#elif defined(CONFIG_X86_32)

#define WORD        .long
#define WORD_SIZE   4
#define AX          %eax
#define BX          %ebx
#define CX          %ecx
#define SP          %esp
#define CODETYPE    .code32

#elif defined(CONFIG_ARM)

#define WORD	.long

#else

#error "Unknown arch!"

#endif


.data
	/* a spin lock */
	_wrp_lock:			WORD	0
	/* points to the last function that was called - protected by the spin lock */
	wrapper_curfunc:	WORD	0


.text
	.global wrapper_start
	.global wrapper_end

	.global wrapper_callback
	.global wrapper_curfunc

	.global wrapper_unlock

#if defined(CONFIG_X86_32) || defined(CONFIG_X86_64)

	CODETYPE

	/* unlock the spin lock */
	wrapper_unlock:
		/* save state */
		xor AX, AX
		mov AX, (_wrp_lock)
		ret


	/* This is the wrapping function. we don't know what the calling convension is
	 * so we leave the stack exactly like it was we we got here. */
	wrapper_start:
		/* this word will be used to return to the callback */
		push AX

		/* save state */
		push AX
		push BX
		push CX

		/* get our location */
		call get_location
	_wrp_location:

		/* get the lock's address */
		lea (_wrp_lock_ptr - _wrp_location)(AX), AX /* get lock_ptr's address */
		mov (AX), BX

		/* lock the spinlock */
		mov $1, CX
	_wrp_again:
		lock xchg (BX), CX
		test CX, CX
		jnz _wrp_again

		/* put our function's address in the cur_func var */
		lea (_wrp_curfunc_ptr - _wrp_lock_ptr)(AX), AX /* get cur_func_ptr's address */
		mov (AX), BX
		lea (wrapper_start - _wrp_curfunc_ptr)(AX), AX /* get this function's address */
		mov AX, (BX)

		/* put the callback in the stack */
		lea (wrapper_callback - wrapper_start)(AX), AX /* update the return value */
		mov (AX), BX
		mov BX, (3 * WORD_SIZE)(SP)

		/* restore state */
		pop CX
		pop BX
		pop AX

		ret

	/* get current location - must be inside the copied area */
	get_location:
		mov (SP), AX
		ret

#elif defined(CONFIG_ARM)

	wrapper_unlock:
		push {r0,r1,lr}
		bl get_location
	_unlk_location:
		mov r1, #0
		ldr r0, [r0, #(_wrp_lock_ptr - _unlk_location)]
		str r1, [r0]
		pop {r0,r1,pc}

	wrapper_start:
		push {r0}
		push {r0-r3,lr}

		bl get_location
	_wrp_location:
		ldr r1, [r0, #(_wrp_lock_ptr - _wrp_location)]

		mov r3, #1
	_wrp_again:
#if __LINUX_ARM_ARCH__ > 5
		ldrex r2, [r1]
		teq r2, #0
		strexeq r2, r3, [r1]
		teqeq r2, #0
#else
		swp r2, r3, [r1]
		cmp r2, #0
#endif
		bne _wrp_again

		ldr r1, [r0, #(_wrp_curfunc_ptr - _wrp_location)]
		ldr r2, [r0, #(wrapper_start - _wrp_location)]
		str r2, [r1]

		ldr r1, [r0, #(wrapper_callback - _wrp_location)]

		str r1, [sp, #0x14]
		
		pop {r0-r3,lr,pc}

	get_location:
		mov r0, lr
		mov pc, lr



#endif
	_wrp_lock_ptr:		WORD	_wrp_lock
	_wrp_curfunc_ptr:	WORD	wrapper_curfunc
	wrapper_callback:	WORD	0
	wrapper_end:

