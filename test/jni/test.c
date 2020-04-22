#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define int FORKS = 0
#define int pid = 0
#define int ppid = 0



int
main(int argc, char **argv)
{
	pid_t pid = getpid();
	pid_t ppid = getppid();
	int fd = open("/data/local/tmp/log.log", O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, S_IROTH|S_IWOTH);
	if (fd){
		char buffer [50];
		int n;
		n=sprintf(buffer, "execl() called from %d, with parent %d\n", pid, ppid);
		write(fd, buffer, n);
		close(fd);
	}
	return 0;
}
