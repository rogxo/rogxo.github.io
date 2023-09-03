```lua
.CODE
PUBLIC GetKernelBase
GetKernelBase PROC
    mov     rax, qword ptr gs:[18h]	;KPCR
    mov     rcx, [rax+38h]	;IdtBase
    mov     rax, 0FFFFFFFFFFFFF000h
    and     rax, [rcx+4h]	;(IdtBase + 4) & 0xFFFFFFFFFFFFF000
    jmp      while_start
search_mem_start:
    add     rax, 0FFFFFFFFFFFFF000h
while_start: 
    xor     ecx, ecx
    jmp      search_mem_check
search_mem_next: 
    add     rcx, 1
    cmp     rcx, 0FF9h
    jz       search_mem_start
search_mem_check:  
    cmp     byte ptr[rax+rcx], 48h
    jnz     search_mem_next
    cmp     byte ptr[rax+rcx+1], 8Dh
    jnz     search_mem_next
    cmp     byte ptr[rax+rcx+2], 1Dh
    jnz     search_mem_next
    cmp     byte ptr[rax+rcx+6], 0FFh
    jnz     search_mem_next
    mov     r8d,[rax+rcx+3]
    lea     edx,[rcx+r8]
    add     edx, eax
    add     edx, 7
    test    edx, 0FFFh
    jnz      search_mem_next
    mov     rdx, 0FFFFFFFF00000000h
    and     rdx, rax
    add     r8d, eax
    lea     eax,[rcx+r8]
    add     eax, 7
    or      rax, rdx
    ret     
GetKernelBase ENDP
END
```