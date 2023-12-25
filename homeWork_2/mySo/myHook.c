#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <elf.h>
#include <fcntl.h>


//表明注入成功
int hookEntry(){
    printf("Inject success, pid = %d\n", getpid());
    printf("Hello World!\n");
    return 0;
}
//用于hook crackme1.so，改变关键流程
int hook(){
    return 1;
}