## 环境：Win7 x64 ntoskrnl.exe

```asm
;;;;;;;;;;;;;;完整反汇编;;;;;;;;;;;;;;;;
PAGE:000000014048A030 ; NTSTATUS __stdcall ObRegisterCallbacks(POB_CALLBACK_REGISTRATION CallbackRegistration, PVOID *RegistrationHandle)
PAGE:000000014048A030                 public ObRegisterCallbacks
PAGE:000000014048A030 ObRegisterCallbacks proc near           ; DATA XREF: .pdata:0000000140296AF4↑o
PAGE:000000014048A030
PAGE:000000014048A030 arg_0           = qword ptr  8
PAGE:000000014048A030 arg_8           = qword ptr  10h
PAGE:000000014048A030 arg_10          = qword ptr  18h
PAGE:000000014048A030 arg_18          = qword ptr  20h
PAGE:000000014048A030
PAGE:000000014048A030                 mov     rax, rsp
PAGE:000000014048A033                 mov     [rax+8], rbx
PAGE:000000014048A037                 mov     [rax+18h], rbp
PAGE:000000014048A03B                 mov     [rax+20h], rsi
PAGE:000000014048A03F                 mov     [rax+10h], rdx
PAGE:000000014048A043                 push    rdi
PAGE:000000014048A044                 push    r12
PAGE:000000014048A046                 push    r13
PAGE:000000014048A048                 push    r14
PAGE:000000014048A04A                 push    r15
PAGE:000000014048A04C                 sub     rsp, 20h
PAGE:000000014048A050                 movzx   eax, word ptr [rcx]
PAGE:000000014048A053                 xor     ebx, ebx
PAGE:000000014048A055                 mov     r12, rcx
PAGE:000000014048A058                 mov     ecx, 0FF00h
PAGE:000000014048A05D                 mov     r14d, 100h
PAGE:000000014048A063                 mov     r15, rdx
PAGE:000000014048A066                 and     ax, cx
PAGE:000000014048A069                 mov     esi, ebx
PAGE:000000014048A06B                 cmp     ax, r14w
PAGE:000000014048A06F                 jz      short loc_14048A07B
PAGE:000000014048A071
PAGE:000000014048A071 loc_14048A071:                          ; CODE XREF: ObRegisterCallbacks+51↓j
PAGE:000000014048A071                 mov     eax, 0C000000Dh
PAGE:000000014048A076                 jmp     loc_14048A2D9
PAGE:000000014048A07B ; ---------------------------------------------------------------------------
PAGE:000000014048A07B
PAGE:000000014048A07B loc_14048A07B:                          ; CODE XREF: ObRegisterCallbacks+3F↑j
PAGE:000000014048A07B                 cmp     [r12+2], bx
PAGE:000000014048A081                 jz      short loc_14048A071
PAGE:000000014048A083                 movzx   ecx, word ptr [r12+2]
PAGE:000000014048A089                 movzx   eax, word ptr [r12+8]
PAGE:000000014048A08F                 mov     r8d, 6C46624Fh  ; Tag
PAGE:000000014048A095                 shl     ecx, 6
PAGE:000000014048A098                 lea     ebp, [rcx+rax+20h]
PAGE:000000014048A09C                 mov     ecx, 1          ; PoolType
PAGE:000000014048A0A1                 mov     edx, ebp        ; NumberOfBytes
PAGE:000000014048A0A3                 mov     r13d, ebp
PAGE:000000014048A0A6                 call    ExAllocatePoolWithTag
PAGE:000000014048A0AB                 mov     rdi, rax
PAGE:000000014048A0AE                 cmp     rax, rbx
PAGE:000000014048A0B1                 jnz     short loc_14048A0BD
PAGE:000000014048A0B3                 mov     eax, 0C000009Ah
PAGE:000000014048A0B8                 jmp     loc_14048A2D9
PAGE:000000014048A0BD ; ---------------------------------------------------------------------------
PAGE:000000014048A0BD
PAGE:000000014048A0BD loc_14048A0BD:                          ; CODE XREF: ObRegisterCallbacks+81↑j
PAGE:000000014048A0BD                 mov     r8, r13         ; Size
PAGE:000000014048A0C0                 xor     edx, edx        ; Val
PAGE:000000014048A0C2                 mov     rcx, rax        ; void *
PAGE:000000014048A0C5                 call    memset
PAGE:000000014048A0CA                 mov     [rdi], r14w
PAGE:000000014048A0CE                 mov     rax, [r12+18h]
PAGE:000000014048A0D3                 mov     [rdi+8], rax
PAGE:000000014048A0D7                 movzx   edx, word ptr [r12+8]
PAGE:000000014048A0DD                 sub     ebp, edx
PAGE:000000014048A0DF                 mov     [rdi+12h], dx
PAGE:000000014048A0E3                 mov     [rdi+10h], dx
PAGE:000000014048A0E7                 mov     r8, rdx         ; Size
PAGE:000000014048A0EA                 mov     ecx, ebp
PAGE:000000014048A0EC                 add     rcx, rdi        ; void *
PAGE:000000014048A0EF                 mov     [rdi+18h], rcx
PAGE:000000014048A0F3                 mov     rdx, [r12+10h]  ; Src
PAGE:000000014048A0F8                 call    memmove
PAGE:000000014048A0FD                 mov     r14d, ebx
PAGE:000000014048A100                 cmp     bx, [r12+2]
PAGE:000000014048A106                 jnb     loc_14048A2AD
PAGE:000000014048A10C                 mov     rbp, rbx
PAGE:000000014048A10F                 lea     r13, [rdi+58h]
PAGE:000000014048A113
PAGE:000000014048A113 loc_14048A113:                          ; CODE XREF: ObRegisterCallbacks+199↓j
PAGE:000000014048A113                 mov     rsi, [r12+20h]
PAGE:000000014048A118                 cmp     [rsi+rbp+8], ebx
PAGE:000000014048A11C                 jz      loc_14048A1D8
PAGE:000000014048A122                 mov     rax, [rsi+rbp]
PAGE:000000014048A126                 mov     rcx, [rax]
PAGE:000000014048A129                 test    byte ptr [rcx+42h], 40h
PAGE:000000014048A12D                 jz      loc_14048A1D8
PAGE:000000014048A133                 mov     rcx, [rsi+rbp+10h]
PAGE:000000014048A138                 cmp     rcx, rbx
PAGE:000000014048A13B                 jnz     short loc_14048A14D ; Verify PreCallback
PAGE:000000014048A13D                 cmp     [rsi+rbp+18h], rbx
PAGE:000000014048A142                 jz      loc_14048A1D8
PAGE:000000014048A148                 cmp     rcx, rbx
PAGE:000000014048A14B                 jz      short loc_14048A156
PAGE:000000014048A14D
PAGE:000000014048A14D loc_14048A14D:                          ; CODE XREF: ObRegisterCallbacks+10B↑j
PAGE:000000014048A14D                 call    MmVerifyCallbackFunction ; <------------- Verify PreCallback
PAGE:000000014048A152                 cmp     eax, ebx
PAGE:000000014048A154                 jz      short loc_14048A1D1
PAGE:000000014048A156
PAGE:000000014048A156 loc_14048A156:                          ; CODE XREF: ObRegisterCallbacks+11B↑j
PAGE:000000014048A156                 mov     rcx, [rsi+rbp+18h]
PAGE:000000014048A15B                 cmp     rcx, rbx
PAGE:000000014048A15E                 jz      short loc_14048A169
PAGE:000000014048A160                 call    MmVerifyCallbackFunction ; <---------------Verify PostCallback
PAGE:000000014048A165                 cmp     eax, ebx
PAGE:000000014048A167                 jz      short loc_14048A1D1
PAGE:000000014048A169
PAGE:000000014048A169 loc_14048A169:                          ; CODE XREF: ObRegisterCallbacks+12E↑j
PAGE:000000014048A169                 mov     [r13+0], rbx
PAGE:000000014048A16D                 lea     rdx, [r13-38h]
PAGE:000000014048A171                 mov     [rdx], rdx
PAGE:000000014048A174                 mov     [r13-30h], rdx
PAGE:000000014048A178                 mov     eax, [rsi+rbp+8]
PAGE:000000014048A17C                 mov     [r13-28h], eax
PAGE:000000014048A180                 mov     [r13-20h], rdi
PAGE:000000014048A184                 mov     rax, [rsi+rbp]
PAGE:000000014048A188                 mov     rcx, [rax]
PAGE:000000014048A18B                 mov     [r13-18h], rcx
PAGE:000000014048A18F                 mov     rax, [rsi+rbp+10h]
PAGE:000000014048A194                 mov     [r13-10h], rax
PAGE:000000014048A198                 mov     rax, [rsi+rbp+18h]
PAGE:000000014048A19D                 mov     [r13-8], rax
PAGE:000000014048A1A1                 call    ObpInsertCallbackByAltitude
PAGE:000000014048A1A6                 cmp     eax, ebx
PAGE:000000014048A1A8                 mov     esi, eax
PAGE:000000014048A1AA                 jl      short loc_14048A1E5
PAGE:000000014048A1AC                 mov     eax, 1
PAGE:000000014048A1B1                 add     rbp, 20h ; ' '
PAGE:000000014048A1B5                 add     r13, 40h ; '@'
PAGE:000000014048A1B9                 add     [rdi+2], ax
PAGE:000000014048A1BD                 movzx   ecx, word ptr [r12+2]
PAGE:000000014048A1C3                 add     r14d, eax
PAGE:000000014048A1C6                 cmp     r14d, ecx
PAGE:000000014048A1C9                 jb      loc_14048A113
PAGE:000000014048A1CF                 jmp     short loc_14048A1DD
PAGE:000000014048A1D1 ; ---------------------------------------------------------------------------
PAGE:000000014048A1D1
PAGE:000000014048A1D1 loc_14048A1D1:                          ; CODE XREF: ObRegisterCallbacks+124↑j
PAGE:000000014048A1D1                                         ; ObRegisterCallbacks+137↑j
PAGE:000000014048A1D1                 mov     esi, 0C0000022h
PAGE:000000014048A1D6                 jmp     short loc_14048A1E5
PAGE:000000014048A1D8 ; ---------------------------------------------------------------------------
PAGE:000000014048A1D8
PAGE:000000014048A1D8 loc_14048A1D8:                          ; CODE XREF: ObRegisterCallbacks+EC↑j
PAGE:000000014048A1D8                                         ; ObRegisterCallbacks+FD↑j ...
PAGE:000000014048A1D8                 mov     esi, 0C000000Dh
PAGE:000000014048A1DD
PAGE:000000014048A1DD loc_14048A1DD:                          ; CODE XREF: ObRegisterCallbacks+19F↑j
PAGE:000000014048A1DD                 cmp     esi, ebx
PAGE:000000014048A1DF                 jge     loc_14048A2AD
PAGE:000000014048A1E5
PAGE:000000014048A1E5 loc_14048A1E5:                          ; CODE XREF: ObRegisterCallbacks+17A↑j
PAGE:000000014048A1E5                                         ; ObRegisterCallbacks+1A6↑j
PAGE:000000014048A1E5                 mov     r12d, ebx
PAGE:000000014048A1E8                 cmp     bx, [rdi+2]
PAGE:000000014048A1EC                 jnb     loc_14048A29E
PAGE:000000014048A1F2                 lea     rbp, [rdi+40h]
PAGE:000000014048A1F6                 mov     r14d, 0B0h
PAGE:000000014048A1FC                 mov     r13d, 1
PAGE:000000014048A202
PAGE:000000014048A202 loc_14048A202:                          ; CODE XREF: ObRegisterCallbacks+268↓j
PAGE:000000014048A202                 mov     rax, gs:188h
PAGE:000000014048A20B                 dec     word ptr [rax+1C6h]
PAGE:000000014048A212                 mov     rcx, [rbp+0]
PAGE:000000014048A216                 add     rcx, r14
PAGE:000000014048A219                 lock bts qword ptr [rcx], 0
PAGE:000000014048A21F                 jnb     short loc_14048A226
PAGE:000000014048A221                 call    ExfAcquirePushLockExclusive
PAGE:000000014048A226
PAGE:000000014048A226 loc_14048A226:                          ; CODE XREF: ObRegisterCallbacks+1EF↑j
PAGE:000000014048A226                 mov     rax, [rbp-18h]
PAGE:000000014048A22A                 mov     rcx, [rbp-20h]
PAGE:000000014048A22E                 mov     [rax], rcx
PAGE:000000014048A231                 mov     [rcx+8], rax
PAGE:000000014048A235                 mov     rdx, [rbp+0]
PAGE:000000014048A239                 add     rdx, r14
PAGE:000000014048A23C                 prefetchw byte ptr [rdx]
PAGE:000000014048A23F                 mov     rax, [rdx]
PAGE:000000014048A242                 mov     rcx, rax
PAGE:000000014048A245                 and     rcx, 0FFFFFFFFFFFFFFF0h
PAGE:000000014048A249                 cmp     rcx, 10h
PAGE:000000014048A24D                 lea     rcx, [rax-10h]
PAGE:000000014048A251                 ja      short loc_14048A256
PAGE:000000014048A253                 mov     rcx, rbx
PAGE:000000014048A256
PAGE:000000014048A256 loc_14048A256:                          ; CODE XREF: ObRegisterCallbacks+221↑j
PAGE:000000014048A256                 test    al, 2
PAGE:000000014048A258                 jnz     short loc_14048A261
PAGE:000000014048A25A                 lock cmpxchg [rdx], rcx
PAGE:000000014048A25F                 jz      short loc_14048A269
PAGE:000000014048A261
PAGE:000000014048A261 loc_14048A261:                          ; CODE XREF: ObRegisterCallbacks+228↑j
PAGE:000000014048A261                 mov     rcx, rdx
PAGE:000000014048A264                 call    ExfReleasePushLock
PAGE:000000014048A269
PAGE:000000014048A269 loc_14048A269:                          ; CODE XREF: ObRegisterCallbacks+22F↑j
PAGE:000000014048A269                 mov     rax, gs:188h
PAGE:000000014048A272                 add     [rax+1C6h], r13w
PAGE:000000014048A27A                 jnz     short loc_14048A28A
PAGE:000000014048A27C                 add     rax, 50h ; 'P'
PAGE:000000014048A280                 cmp     [rax], rax
PAGE:000000014048A283                 jz      short loc_14048A28A
PAGE:000000014048A285                 call    KiCheckForKernelApcDelivery
PAGE:000000014048A28A
PAGE:000000014048A28A loc_14048A28A:                          ; CODE XREF: ObRegisterCallbacks+24A↑j
PAGE:000000014048A28A                                         ; ObRegisterCallbacks+253↑j
PAGE:000000014048A28A                 movzx   eax, word ptr [rdi+2]
PAGE:000000014048A28E                 add     r12d, r13d
PAGE:000000014048A291                 add     rbp, 40h ; '@'
PAGE:000000014048A295                 cmp     r12d, eax
PAGE:000000014048A298                 jb      loc_14048A202
PAGE:000000014048A29E
PAGE:000000014048A29E loc_14048A29E:                          ; CODE XREF: ObRegisterCallbacks+1BC↑j
PAGE:000000014048A29E                 mov     edx, 6C46624Fh  ; Tag
PAGE:000000014048A2A3                 mov     rcx, rdi        ; P
PAGE:000000014048A2A6                 call    ExFreePoolWithTag
PAGE:000000014048A2AB                 jmp     short loc_14048A2D7
PAGE:000000014048A2AD ; ---------------------------------------------------------------------------
PAGE:000000014048A2AD
PAGE:000000014048A2AD loc_14048A2AD:                          ; CODE XREF: ObRegisterCallbacks+D6↑j
PAGE:000000014048A2AD                                         ; ObRegisterCallbacks+1AF↑j
PAGE:000000014048A2AD                 cmp     bx, [rdi+2]
PAGE:000000014048A2B1                 jnb     short loc_14048A2D4
PAGE:000000014048A2B3                 lea     rcx, [rdi+34h]
PAGE:000000014048A2B7                 mov     r15d, 1
PAGE:000000014048A2BD
PAGE:000000014048A2BD loc_14048A2BD:                          ; CODE XREF: ObRegisterCallbacks+29D↓j
PAGE:000000014048A2BD                 or      [rcx], r15d
PAGE:000000014048A2C0                 movzx   eax, word ptr [rdi+2]
PAGE:000000014048A2C4                 add     ebx, r15d
PAGE:000000014048A2C7                 add     rcx, 40h ; '@'
PAGE:000000014048A2CB                 cmp     ebx, eax
PAGE:000000014048A2CD                 jb      short loc_14048A2BD
PAGE:000000014048A2CF                 mov     r15, [rsp+48h+arg_8]
PAGE:000000014048A2D4
PAGE:000000014048A2D4 loc_14048A2D4:                          ; CODE XREF: ObRegisterCallbacks+281↑j
PAGE:000000014048A2D4                 mov     [r15], rdi
PAGE:000000014048A2D7
PAGE:000000014048A2D7 loc_14048A2D7:                          ; CODE XREF: ObRegisterCallbacks+27B↑j
PAGE:000000014048A2D7                 mov     eax, esi
PAGE:000000014048A2D9
PAGE:000000014048A2D9 loc_14048A2D9:                          ; CODE XREF: ObRegisterCallbacks+46↑j
PAGE:000000014048A2D9                                         ; ObRegisterCallbacks+88↑j
PAGE:000000014048A2D9                 mov     rbx, [rsp+48h+arg_0]
PAGE:000000014048A2DE                 mov     rbp, [rsp+48h+arg_10]
PAGE:000000014048A2E3                 mov     rsi, [rsp+48h+arg_18]
PAGE:000000014048A2E8                 add     rsp, 20h
PAGE:000000014048A2EC                 pop     r15
PAGE:000000014048A2EE                 pop     r14
PAGE:000000014048A2F0                 pop     r13
PAGE:000000014048A2F2                 pop     r12
PAGE:000000014048A2F4                 pop     rdi
PAGE:000000014048A2F5                 retn
PAGE:000000014048A2F5 ObRegisterCallbacks endp
```

## 关键代码：

```asm
PAGE:000000014048A14D loc_14048A14D:                          ; CODE XREF: ObRegisterCallbacks+10B↑j
PAGE:000000014048A14D                 call    MmVerifyCallbackFunction ; <------------- Verify PreCallback
PAGE:000000014048A152                 cmp     eax, ebx
PAGE:000000014048A154                 jz      short loc_14048A1D1
PAGE:000000014048A156
PAGE:000000014048A156 loc_14048A156:                          ; CODE XREF: ObRegisterCallbacks+11B↑j
PAGE:000000014048A156                 mov     rcx, [rsi+rbp+18h]
PAGE:000000014048A15B                 cmp     rcx, rbx
PAGE:000000014048A15E                 jz      short loc_14048A169
PAGE:000000014048A160                 call    MmVerifyCallbackFunction ; <---------------Verify PostCallback
PAGE:000000014048A165                 cmp     eax, ebx
PAGE:000000014048A167                 jz      short loc_14048A1D1
```

## nop掉两处MmVerifyCallbackFunction