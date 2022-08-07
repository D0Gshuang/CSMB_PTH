# CSMB_PTH

CSMB_PTH 用于学习NTLM协议的练习项目,因为没找到有人用C去实现pth，所以有了该项目。

基于SMB协议进行windows主机远程命令执行的工具 使用纯C进行SMB协议包的构造，实现哈希传递,类似Impacket的实现方式。无回显
主要流程: NTLM -> IPC -> RPC
USAGE: csmb.exe username domain IP Hash ServiceName Command

该项目使用额外库为OpenSSL，使用了其HMAC_MD5模块

相关SMB结构借鉴于: https://github.com/Kevin-Robertson/Invoke-TheHash
