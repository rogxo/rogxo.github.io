## 近期跟海哥学习了系统底层的一些知识，此处使用IDA对MmIsAddressValid进行逆向分析，以加深对Windows分页机制的了解
废话不多说，上代码

* * *

```Assembly
;环境:Windows7 x32 ntoskrnl.exe 非PAE模式
.text:00409F4C                   ; BOOLEAN __stdcall MmIsAddressValid(PVOID VirtualAddress)
.text:00409F4C                                   public _MmIsAddressValid@4
.text:00409F4C                   _MmIsAddressValid@4 proc near           ; CODE XREF: IopIsAddressRangeValid(x,x)+31↑p
.text:00409F4C
.text:00409F4C                   VirtualAddress  = dword ptr  8
.text:00409F4C
.text:00409F4C 8B FF                             mov     edi, edi        ; HotFix，微软的热补丁技术
.text:00409F4E 55                                push    ebp
.text:00409F4F 8B EC                             mov     ebp, esp        ; 建立ebp-esp栈帧
.text:00409F51 8B 4D 08                          mov     ecx, [ebp+8] ; ecx = VirtualAddresss
.text:00409F54 E8 6F 34 08 00                    call    _MiIsAddressValid@8
.text:00409F59 5D                                pop     ebp
.text:00409F5A C2 04 00                          retn    4
.text:00409F5A                   _MmIsAddressValid@4 endp

; ---------------------------------------------------------------------------

.text:0048D3C8                   ; __stdcall MiIsAddressValid(x, x)
.text:0048D3C8                   _MiIsAddressValid@8 proc near           ; CODE XREF: MiMakeSystemAddressValidSystemWs(x,x)+E↑p
.text:0048D3C8                                                           ; MiMakeSystemAddressValidSystemWs(x,x)+10C↑p ...
.text:0048D3C8 8B C1                             mov     eax, ecx        ; eax = ecx = VA
.text:0048D3CA C1 E8 14                          shr     eax, 14h        ; VA右移20(14h)位
.text:0048D3CD 25 FC 0F 00 00                    and     eax, 0FFCh      ; VA>>20 & 111111111100 <==> PDI<<2 <==> PDI*4 = Offset
.text:0048D3D2 2D 00 00 D0 3F                    sub     eax, 3FD00000h  ; <==> eax + (~3FD00000h+1) <==> eax + C0300000h = Base(PageDir) + Offset 得到对应页表描述符的地址
.text:0048D3D7 8B 00                             mov     eax, [eax]      ; 读取eax保存的地址里的内容，获取对应页表的描述符并保存在eax里
.text:0048D3D9 A8 01                             test    al, 1           ; 取页表描述符的最后一位Present(有效)位(0-7属性,8-11 Ignored,12-31为BaseAddr)是否为0
.text:0048D3DB 75 03                             jnz     short loc_48D3E0; 页表不存在则返回FALSE
.text:0048D3DD
.text:0048D3DD                   loc_48D3DD:
.text:0048D3DD 32 C0                             xor     al, al          ; bRet = FALSE
.text:0048D3DF C3                                retn                    ; Return FALSE;
.text:0048D3E0                   ; ---------------------------------------------------------------------------
.text:0048D3E0
.text:0048D3E0                   loc_48D3E0:
.text:0048D3E0 84 C0                             test    al, al          ; 以al为操作数，修正eflags.sf位，目的是为了获取第八位PS位，进而判断是不是4MB大页
.text:0048D3E2 79 03                             jns     short loc_48D3E7; 判断符号位(这里以符号位代指第七位PS位)是否为1,为1则说明为4MB大页,eax直指物理地址,所以返回TRUE
.text:0048D3E2                                                           ; 为0则是4KB页页表的描述符,且页表的描述符有效,进而判断物理页是否有效
.text:0048D3E4 B0 01                             mov     al, 1           ; return TRUE;
.text:0048D3E6 C3                                retn
.text:0048D3E7                   ; ---------------------------------------------------------------------------
.text:0048D3E7
.text:0048D3E7                   loc_48D3E7:
.text:0048D3E7 C1 E9 0A                          shr     ecx, 0Ah        ; VA右移10位
.text:0048D3EA 81 E1 FC FF 3F 00                 and     ecx, 3FFFFCh    ; & 001111111111111111111100,掩码掩掉最后两位,相当于((VA>>12)<<2)
.text:0048D3F0 81 E9 00 00 00 40                 sub     ecx, 40000000h  ; C0000000 + (VA>>10) & 3FFFFC
.text:0048D3F6 8B 01                             mov     eax, [ecx]      ; 取到Page Table的描述符
.text:0048D3F8 A8 01                             test    al, 1           ; 判断Present位
.text:0048D3FA 74 E1                             jz      short loc_48D3DD ; Present = 0,return FALSE;
.text:0048D3FC 24 80                             and     al, 80h         ; 低八位 & 80h(10000000),取最高位
.text:0048D3FE 3C 80                             cmp     al, 80h
.text:0048D400 0F 95 C0                          setnz   al
.text:0048D403 C3                                retn
.text:0048D403                   _MiIsAddressValid@8 endp
```