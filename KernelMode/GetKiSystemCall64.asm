.code

GetKiSystemCall64 proc
push rcx
push rdx
mov ecx,0C0000082h
rdmsr
shl rdx,32
and rax,0FFFFFFFFh
or rax,rdx
pop rdx
pop rcx
ret
GetKiSystemCall64 endp

end