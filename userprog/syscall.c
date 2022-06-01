#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "filesys/filesys.h"
#include "filesys/file.h"
#include <list.h>
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/synch.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *);             /* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 잘못된 접근일 결우 프로세스 종료 */
void get_argument(void *, int *, int);  /* 유저 스택에 저장된 인자값들을 커널로 저장, 인자가 저장된 위치가 유저영역인지 확인 */
/* 시스템 콜 */
void halt(void);                        /* pintos를 종료시키는 시스템 콜 */
void exit(int);                         /* 현재 프로세스를 종료시키는 시스템 콜 */
bool create(const char *, unsigned);    /* 파일을 생성하는 시스템 콜 */
bool remove(const char *);              /* 파일을 삭제하는 시스템 콜 */
int exec(const char *);
int wait(int);
tid_t fork (const char *, struct intr_frame *);

/* 파일 관련 시스템 콜 */
const int STDIN = 0;
const int STDOUT = 1;
struct lock file_rw_lock;
int open(const char *);
int add_file_to_fdt(struct file *);
static struct file *fd_to_struct_file(int);
void remove_file_from_fdt(int);
int filesize(int);
int read(int, void *, unsigned);
int write(int, const void *, unsigned);
void seek (int, unsigned);
unsigned tell (int);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&file_rw_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// check_address(f);
	int sys_number = f->R.rax; 

	switch(sys_number) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;		
		case SYS_EXEC:
			exec(f->R.rdi);
			break;
		case SYS_WAIT:
			wait(f->R.rdi);
			break;
		case SYS_CREATE:
			create(f->R.rdi, f->R.rsi);
			break;		
		case SYS_REMOVE:
			remove(f->R.rdi);
			break;		
		case SYS_OPEN:
			open(f->R.rdi);
			break;		
		case SYS_FILESIZE:
			filesize(f->R.rdi);
			break;
		case SYS_READ:
			read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			write(f->R.rdi, f->R.rsi, f->R.rdx);		
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;		
		case SYS_TELL:
			tell(f->R.rdi);
			break;		
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:
			printf ("system call!\n");
			thread_exit ();
	}
}
/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 잘못된 접근일 경우 프로세스 종료 */
void check_address(void *addr) {
	struct thread *curr = thread_current();
	if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(curr->pml4, addr) == NULL) {
		exit(-1);
	}
}      
/* 유저 스택에 저장된 인자값들을 커널로 저장, 인자가 저장된 위치가 유저영역인지 확인 */   
void get_argument(void *rsp, int *arg, int cnt) {
	int *rsp_ = rsp; 
	for (int i = 0; i < cnt; i++) {
		check_address(&rsp_[i]);
		check_address(&arg[i]);
		arg[i] = rsp_[i];
	}
}
/* pintos를 종료시키는 시스템 콜 */
void halt(void) {
	power_off();
}

/* 현재 프로세스를 종료시키는 시스템 콜 */                       
void exit(int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status;

	printf("%s: exit(%d)", curr->name, status);
	thread_exit();
}

/* 파일을 생성하는 시스템 콜 */                        
bool create(const char *file, unsigned initial_size) {
	check_address(file);
	return filesys_create(file, initial_size);
}

/* 파일을 삭제하는 시스템 콜 */    
bool remove(const char *file) {
	check_address(file);
	return filesys_remove(file);
}

/* 자식 프로세스를 생성하고 프로그램을 실행시키는 시스템 콜 */
int exec(const char *cmd_line) {
	check_address(cmd_line);

	int size = strlen(cmd_line) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO);
	
	if (fn_copy == NULL) {
		exit(-1);
	}
	strlcpy(fn_copy, cmd_line, size);

	if (process_exec(fn_copy) == -1) {
		return -1;
	}

	NOT_REACHED();

	return 0;
}

int wait(int tid) {
	process_wait(tid);
}

tid_t fork (const char *thread_name, struct intr_frame *f)
{
	return process_fork(thread_name, f);
}

/*----------------------------file------------------------------*/

/*----------------------------helper function start------------------------------*/
int add_file_to_fdt(struct file *fileobj) {
	struct thread *curr = thread_current();
	curr->fdTable[++curr->fdIdx] = fileobj;
	return curr->fdIdx;
}

static struct file *fd_to_struct_file(int fd) {
	struct thread *curr = thread_current();
	struct file *file = curr->fdTable[fd];
	check_address(file);
	if (file == NULL || fd < 0 || fd >= FDCOUNT_LIMIT) return NULL;
	return file;
}

void remove_file_from_fdt(int fd) {
	struct thread *curr = thread_current();
	if (fd < 0 || fd >= FDCOUNT_LIMIT) return;
	curr->fdTable[fd] = NULL;
}
/*----------------------------helper function end------------------------------*/

int open(const char *file) {
	check_address(file);
	struct file *fileobj = filesys_open(file);
	int fd = add_file_to_fdt(fileobj);
	if (fileobj == NULL || fd < 0 || fd >= FDCOUNT_LIMIT) return -1;
	return fd;
}

int filesize(int fd) {
	struct file *fileobj = fd_to_struct_file(fd);
	if (fileobj == NULL) return -1;
	return file_length(fileobj);
}

int read(int fd, void *buffer, unsigned size) {
	check_address(buffer);
	int ret;
	struct thread *curr = thread_current();
	struct file *fileobj = fd_to_struct_file(fd);

	if (fileobj == NULL) return -1;

	if (fd == STDIN) {
		// if (curr->stdin_count == 0) {
		// 	// Not reachable
		// 	NOT_REACHED();
		// 	remove_file_from_fdt(fd);
		// 	ret = -1;
		// }
		// else {
			int i;
			unsigned char *buf = buffer;
			
			/* 키보드로 적은(버퍼) 내용 받아옴 */
			for (i = 0; i < size; i++) {
				char c = input_getc();
				*buf++ = c;
				if (c == '\0')
					break;
			}
			ret = i;
		// }
	}
	else if (fd == STDOUT) {
		ret = -1;
	}
	else {
		lock_acquire(&file_rw_lock);
		ret = file_read(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}
	return ret;
}

int write(int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	int ret;
	struct thread *curr = thread_current();
	struct file *fileobj = fd_to_struct_file(fd);

	if (fileobj == NULL) return -1;
	
	if (fd == STDOUT) {
		// if(curr->stdout_count == 0) {
		// 	//Not reachable
		// 	NOT_REACHED();
		// 	remove_file_from_fdt(fd);
		// 	ret = -1;
		// }
		// else
		// {
			/* 버퍼를 콘솔에 출력 */
			putbuf(buffer, size);
			ret = size;
		// }
	}
	else if (fd == STDIN) {
		ret = -1;
	} 
	else {
		lock_acquire(&file_rw_lock);
		ret = file_write(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}
	return ret;
}

void seek(int fd, unsigned position) {
	if (fd < 2) return;
	struct file *fileobj = fd_to_struct_file(fd);
	if (fileobj == NULL) return;
	file_seek(fileobj, position);
}

unsigned tell(int fd) {
	if (fd < 2) return;
	struct file *fileobj = fd_to_struct_file(fd);
	if (fileobj == NULL) return;
	return file_tell(fileobj);
}

void close(int fd){
	struct file *fileobj = fd_to_struct_file(fd);
	if (fileobj == NULL) return;
	
	struct thread *cur = thread_current();
	
	if (fd == STDIN) {
		cur->stdin_count--;
	}
	else if (fd == STDOUT) {
		cur->stdout_count--;
	}
	
	remove_file_from_fdt(fd);
}