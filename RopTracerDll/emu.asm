[bits 64]

global _emulateRetInstruction

section .text 
    _emulateRetInstruction:
        mov rax, rcx
        ret

        ; Save registers
        push    rdi
        push    rsi
        push    rbp
        push    rbx
        push    rdx
        push    rcx
        push    rax

        ; Restore registers
        pop rax
        pop rcx
        pop rdx
        pop rbx
        pop rbp
        pop rsi
        pop rdi
        popf

        ret

section .data
    newRsp: dq 0
    originalRsp: dq 0