/*
* Tencent is pleased to support the open source community by making Libco available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, 
* software distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License.
*/
// 详细分析：https://zhuanlan.zhihu.com/p/27409164

.globl coctx_swap
#if !defined( __APPLE__ ) && !defined( __FreeBSD__ )
.type  coctx_swap, @function
#endif
coctx_swap:

#if defined(__i386__)
	leal 4(%esp), %eax //sp 
	movl 4(%esp), %esp 
	leal 32(%esp), %esp //parm a : &regs[7] + sizeof(void*)

	pushl %eax //esp ->parm a 

	pushl %ebp
	pushl %esi
	pushl %edi
	pushl %edx
	pushl %ecx
	pushl %ebx
	pushl -4(%eax)

	
	movl 4(%eax), %esp //parm b -> &regs[0]

	popl %eax  //ret func addr
	popl %ebx  
	popl %ecx
	popl %edx
	popl %edi
	popl %esi
	popl %ebp
	popl %esp
	pushl %eax //set ret func addr

	xorl %eax, %eax
	ret

#elif defined(__x86_64__)
	leaq 8(%rsp),%rax	// rax = rsp + 8  // +8表示跳过上一层栈帧压入的返回地址 rax指向调用coctx_swap之前的堆栈栈顶
	leaq 112(%rdi),%rsp	// rsp = rdi + 112 【切换栈】 即rsp指向curr->ctx->regs数组尾
	pushq %rax			// curr->ctx->regs[13] = rax
	pushq %rbx			// curr->ctx->regs[12] = rbx
	pushq %rcx			// curr->ctx->regs[11] = rcx
	pushq %rdx			// curr->ctx->regs[10] = rdx

	pushq -8(%rax) //ret func addr	// curr->ctx->regs[9] = rax-8  // 指向上一层堆栈压入的返回地址 即函数coctx_swap下一行

	pushq %rsi			// curr->ctx->regs[8] = rsi
	pushq %rdi			// curr->ctx->regs[7] = rdi
	pushq %rbp			// curr->ctx->regs[6] = rbp
	pushq %r8			// curr->ctx->regs[5] = r8
	pushq %r9			// curr->ctx->regs[4] = r9
	pushq %r12			// curr->ctx->regs[3] = r12
	pushq %r13			// curr->ctx->regs[2] = r13
	pushq %r14			// curr->ctx->regs[1] = r14
	pushq %r15			// curr->ctx->regs[0] = r15
	
	movq %rsi, %rsp		// rsp = rsi 【切换栈】 即rsp指向pending_co->ctx->regs数组头
	popq %r15			// r15 = curr->ctx->regs[0]
	popq %r14			// r14 = curr->ctx->regs[1]
	popq %r13			// r13 = curr->ctx->regs[2]
	popq %r12			// r12 = curr->ctx->regs[3]
	popq %r9			// r9 = curr->ctx->regs[4]
	popq %r8			// r8 = curr->ctx->regs[5]
	popq %rbp			// rbp = curr->ctx->regs[6]
	popq %rdi			// rdi = curr->ctx->regs[7]
	popq %rsi			// rsi = curr->ctx->regs[8]
	popq %rax //ret func addr	// rax = curr->ctx->regs[9] 将要切入的coroutine调用coctx_swap的下一行
	popq %rdx			// rdx = curr->ctx->regs[10]
	popq %rcx			// rcx = curr->ctx->regs[11]
	popq %rbx			// rbx = curr->ctx->regs[12]
	popq %rsp			// rsp = curr->ctx->regs[13] 【切换栈】 即rsp指向之前保存的栈顶指针 将要切入的coroutine调用coctx_swap之前的栈顶
	pushq %rax			// 压入返回地址
	
	xorl %eax, %eax		// 将eax低位清零 作为函数返回值
	ret					// 函数ret  相当于pop rip 弹出刚压入的返回地址作为指令寄存器的值 接着执行调用coctx_swap的下一行代码
#endif
