#include "stats_collector.h"
#include <sys/syscall.h>
#include <unistd.h>

void stats_collector::generate_syscall(uint16_t syscall_id)
{
	switch(syscall_id)
	{

#ifdef __NR_open
	case __NR_open:
		syscall(__NR_open, "tmp", 0);
		break;
#endif /*__NR_open */

#ifdef __NR_execveat
	case __NR_execveat:
		syscall(__NR_execveat, 0, "null", NULL, NULL, 0);
		break;
#endif /*__NR_execveat */

#ifdef __NR_clone3
	case __NR_clone3:
		syscall(__NR_clone3, NULL, 0);
		break;
#endif /* __NR_clone3 */

#ifdef __NR_dup3
	case __NR_dup3:
		syscall(__NR_dup3, -1, -1, 0);
		break;
#endif /*__NR_dup3 */

#ifdef __NR_clone
	case __NR_clone:
		syscall(__NR_clone, -1, 0, NULL, NULL, 0);
		break;
#endif /*__NR_clone */

#ifdef __NR_connect
	case __NR_connect:
		syscall(__NR_connect, -1, NULL, 0);
		break;
#endif /* __NR_connect */

#ifdef __NR_copy_file_range
	case __NR_copy_file_range:
		syscall(__NR_copy_file_range, -3, 0, -4, 0, 0, 0);
		break;
#endif /* __NR_connect */

	default:
		break;
	}
}
