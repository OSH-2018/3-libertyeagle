# OSH Lab 3   
Email: <wuyongji317@gmail.com>   
**本程序用到了`math.h`，因此需要使用`-lm`参数编译**   
完整的编译指令如下   
`gcc -D_FILE_OFFSET_BITS=64 -o oshfs oshfc -lfuse -lm`   
- 使用implicit free list + first fit管理文件系统地址空间
- 支持`chmod`, `chown`操作