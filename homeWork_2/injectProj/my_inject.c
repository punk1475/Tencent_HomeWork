#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include<sys/wait.h>
#include <sys/user.h>
#include "asm/ptrace.h"
#include <sys/mman.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <jni.h>

#define MAX_PATH_LEN 260
#define LIBC_NAME "/apex/com.android.runtime/lib/bionic/libc.so"
#define LINKER_NAME "libdl.so"
//放在软件包中
#define MY_LIB "libmyHook.so"
#define HOOKED_SO "libcrackme1.so"
#define NEW_FUNC_NAME "hook"
#define ALIGN_MASK (sizeof(long)-1)
#define ALIGN_NUM (sizeof (long))
#define MY_PAGE_SIZE 0x1000
#define MY_PAGE_MASK (MY_PAGE_SIZE-1)
//用于计算按long向上对齐后的大小
#define align(x) (((x)+ALIGN_MASK)&(~ALIGN_MASK))
//用在mmap时，保证一定能够拿到对齐的地址
#define alignedSize(sz) ((sz)+ALIGN_NUM)
//用于mmap时按页对齐
#define alignToPage(x) (((x)+MY_PAGE_MASK)&(~MY_PAGE_MASK))
#define HOOK_CODE_SIZE 8
#define STUB_BLOCK_SIZE 20
#define ORI_BLOCK_SIZE 16

static void *pMmap=mmap;
static void *pDlopen= dlopen;

extern int errno;


/**
 *遍历proc下的不同cmdline文件，利用启动时的命令中的文件路径进行比较，查找与目标文件相近的文件的pid
*/
pid_t findPidByFileName(const char * filename){
    pid_t pid=-1;
    if(filename==NULL){
        return -1;
    }
    DIR * procDir=opendir("/proc");
    struct dirent *pidDir;
    if(procDir){//成功打开/proc文件夹
        while((pidDir=readdir(procDir))!=NULL){//查看/proc下的目录项
            pid_t choosePid=atol(pidDir->d_name);
            char chooseFilePath[MAX_PATH_LEN];
            if(choosePid!=0){//不能为idle进程
                snprintf(chooseFilePath,MAX_PATH_LEN,"/proc/%d/cmdline",choosePid);
                FILE* chooseFile=fopen(chooseFilePath,"r");
                if(chooseFile){
                    char cmdstr[MAX_PATH_LEN];
                    fgets(cmdstr,MAX_PATH_LEN,chooseFile);
                    int offset=strlen(cmdstr);
                    while(offset>=0&&cmdstr[offset]!='/'){
                        offset--;
                    }
                    if(strcmp(filename,(const char*)(cmdstr+offset+1))==0){
                        pid=choosePid;
                        printf("成功获取到目标进程pid!\n");
                        break;
                    }
                }
                fclose(chooseFile);
            }
        }

    }
    return pid;
}
void readRemoteData(pid_t pid,char * remoteData,char * buf,size_t len){
    for(size_t i=0;i<len;i+=sizeof(long)){
        long temp=ptrace(PTRACE_PEEKTEXT,pid,remoteData+i,NULL);
        memcpy(buf+i,&temp,sizeof(long));
    }
    printf("成功读取目标进程数据!\n");
}

void writeRemoteData(pid_t pid,char * remoteBuf,char * data,size_t len){
    for(size_t i=0;i<len;i+=sizeof(long)){
        ptrace(PTRACE_POKETEXT,pid,remoteBuf+i,*(long*)(data+i));
    }
    printf("成功写入目标进程!\n");
}

void* getRemoteModuleBase(pid_t pid,char* moduleName){
    if(moduleName==NULL||pid==0){
        printf("远程进程pid或模块名异常\n");
        return NULL;
    }
    char mapsFilePath[MAX_PATH_LEN];
    if(pid<0){//对应此进程
        snprintf(mapsFilePath,MAX_PATH_LEN,"/proc/self/maps");
    }else{
        snprintf(mapsFilePath,MAX_PATH_LEN,"/proc/%d/maps",pid);
    }

    FILE* mapsFile=fopen(mapsFilePath,"r");
    if(mapsFile){
        char buf[1024];
        while(fgets(buf,sizeof(buf),mapsFile)){
            if(strstr(buf,moduleName)){
                void * base=(void *)strtoul(buf,NULL,16);
                printf("目标进程(pid:%d)对应模块(%s)已找到 基地址为0x%lx\n",pid,moduleName,(unsigned long)base);
                return base;
            }
        }
    }
    printf("目标进程(pid:%d)未找到对应的模块\n",pid);
    return NULL;
}
void* getRemoteFuncAddr(void * thisAddr,pid_t pid,char *moduleName,char * funcName){
    void * thisBase=getRemoteModuleBase(-1,moduleName);
    void * remoteBase=getRemoteModuleBase(pid,moduleName);
    void * remoteFunAddr=(void *)((unsigned long)thisAddr+(unsigned long)remoteBase-(unsigned long)thisBase);
    printf("thisAddr:0x%lx  ,  thisBase:0x%lx  ,  remoteBase:0x%lx\n",(unsigned long)thisAddr,(unsigned long)thisBase,(unsigned long)remoteBase);
    printf("函数（%s）在进程（pid:%d）的地址已找到：0x%lx\n",funcName,pid,(unsigned long)remoteFunAddr);
    return remoteFunAddr;
}

int callRemoteFunc(pid_t pid,void * pRemoteFun,long * argv,unsigned long argc,struct pt_regs *regs){
    unsigned long i=0;
    for(;i<argc&&i<4;i++){
        regs->uregs[i]=argv[i];
    }
    if(i<argc){
        unsigned long len=sizeof(long)*(argc-i);
        regs->ARM_sp-=(long)len;
        writeRemoteData(pid,(void *)regs->ARM_sp,(char *)(argv+i),len);
    }

    //memcpy()
    regs->ARM_pc=(long)pRemoteFun;
    if((long)pRemoteFun&1){
        regs->ARM_pc&=(long)(~1u);
        regs->ARM_cpsr|=(long)(1u<<5);
    }else{
        regs->ARM_cpsr&=(long)(~(1u<<5));
    }

    regs->ARM_lr=0;
    if(ptrace(PTRACE_SETREGS,pid,NULL,regs)<0){
        printf("远程调用中，试图修改寄存器环境时发生错误\n");
        return -1;
    }
    int * status;
    if((ptrace(PTRACE_CONT,pid,NULL,0))<0){
        printf("远程调用中，试图使目标进程继续执行时发生错误\n");
        return -1;
    }
    waitpid(pid,status,WUNTRACED);
    return 0;
}

long getRetVal(pid_t pid){
    struct pt_regs regs;
    if(ptrace(PTRACE_GETREGS,pid,NULL,&regs)<0){
        printf("远程调用中，试图获取目标进程寄存器值发生错误\n");
        return -1;
    }
    if(regs.ARM_r0==-1){
        printf("对应函数执行失败，返回值为-1\n");
        return -1;
    }
    if(regs.ARM_r0==0){
        printf("对应函数执行失败，返回值为0\n");
        return 0;
    }
    return regs.ARM_r0;
}

int inject(pid_t pid){
    if(pid!=-1&&pid!=0){
        if(ptrace(PTRACE_ATTACH,pid,NULL,NULL)<0){
            printf("进程attach失败！\n");
            return -1;
        }
        int status;
        waitpid(pid,&status,0);
        if(ptrace( PTRACE_SYSCALL, pid, NULL, 0  ) < 0){
            printf("进程 syscall 失败！\n");
            return -1;
        }
        waitpid(pid,&status,0);
        struct pt_regs oldRegs;
        if(ptrace(PTRACE_GETREGS,pid,NULL,&oldRegs)<0){
            printf("进程试图保护寄存器环境失败！\n");
            return -1;
        }
        struct pt_regs regs;
        memcpy(&regs,&oldRegs,sizeof (struct pt_regs));
        void * pRemoteMmap= getRemoteFuncAddr(pMmap,pid,LIBC_NAME,"mmap");
        void * pRemoteDlopen= getRemoteFuncAddr(pDlopen,pid,LINKER_NAME,"dlopen");
        long argv[16];
        unsigned argc=6;
        unsigned long len= alignedSize(align(sizeof(MY_LIB))+ align(sizeof(NEW_FUNC_NAME)));
        //准备远程调用mmap创建匿名映射段，放so库名称
        argv[0]=0;
        argv[1]=(long)alignToPage(len);
        argv[2]=PROT_READ | PROT_WRITE | PROT_EXEC;
        argv[3]=MAP_ANONYMOUS | MAP_PRIVATE;
        argv[4]=0;
        argv[5]=0;
        if(callRemoteFunc(pid,pRemoteMmap,argv,argc,&regs)==-1){
            printf("试图远程调用mmap发生错误！\n");
            return -1;
        }
        //获取mmap取得的地址
        unsigned long pRemoteMyLibStr= getRetVal(pid);
        printf("成功获取mmap的返回地址：0x%lx\n",pRemoteMyLibStr);
        writeRemoteData(pid,(char*)pRemoteMyLibStr,MY_LIB,sizeof (MY_LIB));
        unsigned long pRemoteStub= pRemoteMyLibStr + align(sizeof (MY_LIB));
        unsigned long pRemoteOri= pRemoteStub + align(STUB_BLOCK_SIZE);
        argc=2;
        argv[0]=(long)pRemoteMyLibStr;
        argv[1]=RTLD_NOW | RTLD_GLOBAL;
        //装载对应so库
        if(callRemoteFunc(pid,pRemoteDlopen,argv,argc,&regs)==-1){
            printf("试图远程调用dlopen发生错误！\n");
            return -1;
        }
        long handle=getRetVal(pid);
        if(!handle){
            printf("dlopen执行完成，但是存在异常\n");
            argc=0;
            void * pRemoetDlErr=getRemoteFuncAddr(dlerror,pid,LINKER_NAME,"dlerror");
            if(callRemoteFunc(pid,pRemoetDlErr,argv,argc,&regs)==-1){
                printf("试图远程调用dlerror发生错误！\n");
                return -1;
            }
            unsigned long reason=getRetVal(pid);
            void * buff=mmap(0,0x1000,7,34,0,0);
            readRemoteData(pid,(char*)reason,buff,0x1000);
            return -1;
        }

        if(getRemoteModuleBase(pid,MY_LIB)){
            printf("加载的模块my lib已找到！\n");
        }
        //unsigned long pRemoteStub= pRemoteNewFunc + align(sizeof (NEW_FUNC_NAME));
        unsigned long hookedOffset=0x00001180;
        //为thumb格式
        unsigned long myFunOffset=0x00000488+1;
        unsigned long pRemoteMyFun=(unsigned long)getRemoteModuleBase(pid,MY_LIB)+myFunOffset;
        unsigned long pRemoteHookedAddr=(unsigned long)getRemoteModuleBase(pid,HOOKED_SO)+hookedOffset;
        //负责跳转到stub
        //LDR PC,=stubBlock
        char hookCode[HOOK_CODE_SIZE]={0x04,0xf0,0x1f,0xe5};
        *(unsigned long *)(hookCode+4)=pRemoteStub;
        //负责函数调用,共20字节
        //LDR R0,=newFuncAddr
        //BLX R0
        //LDR PC,=oriBlock

        char stubCode[STUB_BLOCK_SIZE]={0x04,0x00,0x1f,0xe5};
        *(unsigned  long*)(stubCode+4)=pRemoteMyFun;
        stubCode[8]=0x30;
        stubCode[9]=0xff;
        stubCode[10]=0x2f;
        stubCode[11]=0xe1;

        stubCode[12]=0x04;
        stubCode[13]=0xf0;
        stubCode[14]=0x1f;
        stubCode[15]=0xe5;
        *(unsigned  long*)(stubCode+16)=pRemoteOri;

        //负责执行原先指令,共16字节
        //AND  R0, R0, #1
        //MOV  SP, R11
        //LDR PC,=hookedAddr+8
        char oriCode[ORI_BLOCK_SIZE]={0x01,0x00,0x00,0xe2,0x0b,0xd0,0xa0,0xe1,0x04,0xf0,0x1f,0xe5};
        *(unsigned  long*)(oriCode+12)=pRemoteHookedAddr+8;

        writeRemoteData(pid,(char*)pRemoteStub,stubCode,STUB_BLOCK_SIZE);
        writeRemoteData(pid,(char*)pRemoteOri,oriCode,ORI_BLOCK_SIZE);
        writeRemoteData(pid,(char*)pRemoteHookedAddr,hookCode,HOOK_CODE_SIZE);
        if(ptrace(PTRACE_SETREGS,pid,NULL,&oldRegs)<0){
            printf("恢复寄存器失败！\n");
            return -1;
        }
        if(ptrace(PTRACE_DETACH,pid,NULL,0)<0){
            printf("detach失败！\n");
            return -1;
        }
        return 0;
    }else{
        printf("pid异常！\n");
        return -1;
    }
}

int main(){
    pid_t pid=findPidByFileName("com.example.crackme1");
    //pid_t pid=findPidByFileName("myTest");
    printf("pid of crackme1 is %d\n",pid);
    if(inject(pid)==-1){
        return -1;
    }
    return 0;
}