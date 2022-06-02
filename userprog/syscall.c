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
/* 시스템 콜 */
void halt(void);                        /* pintos를 종료시키는 시스템 콜 */
void exit(int);                         /* 현재 프로세스를 종료시키는 시스템 콜 */
bool create(const char *, unsigned);    /* 파일을 생성하는 시스템 콜 */
bool remove(const char *);              /* 파일을 삭제하는 시스템 콜 */
int exec(const char *);
int wait(int);
int fork (const char *);

/* 파일 관련 시스템 콜 */
const int STDIN = 0;
const int STDOUT = 1;
struct lock file_rw_lock;
int open(const char *);
void close (int);
int filesize(int);
int read(int, void *, unsigned);
int write(int, const void *, unsigned);
void seek (int, unsigned);
unsigned tell (int);
static struct file *fd_to_struct_file(int);
int add_file_to_fdt(struct file *);
void remove_file_from_fdt(int);

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
	switch(f->R.rax) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK: ;
			struct thread *curr = thread_current();
			memcpy(&curr->parent_if, f, sizeof(struct intr_frame));
			f->R.rax = fork(f->R.rdi);
			break;		
		case SYS_EXEC:
			if (exec(f->R.rdi) == -1) exit(-1);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;		
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;		
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;		
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);		
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;		
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;		
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:
			exit(-1);
	}
}
/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 잘못된 접근일 경우 프로세스 종료 */
void check_address(void *addr) {
	struct thread *curr = thread_current();
	if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(curr->pml4, addr) == NULL) {
		exit(-1);
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
	printf("%s: exit(%d)\n", thread_name(), status);
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
	
	if (fn_copy == NULL) exit(-1);
	strlcpy(fn_copy, cmd_line, size);
	if (process_exec(fn_copy) == -1) return -1;
	NOT_REACHED();
	return 0;
}

int wait(int tid) {
	return process_wait(tid);
}

int fork (const char *thread_name) {
	struct thread *t =  thread_current ();
	return process_fork(thread_name, &t->parent_if);
}

/*----------------------------file------------------------------*/

/*----------------------------helper function start------------------------------*/
int add_file_to_fdt(struct file *fileobj) {
	struct thread *cur = thread_current();
    struct file **fdt = cur->fdTable;

    while (cur->fdIdx < FDCOUNT_LIMIT && fdt[cur->fdIdx]) {
        cur->fdIdx++;
    }

    // error - fd table full
    if (cur->fdIdx >= FDCOUNT_LIMIT) return -1;

    fdt[cur->fdIdx] = fileobj;
    return cur->fdIdx;
}

static struct file *fd_to_struct_file(int fd) {
	struct thread *curr = thread_current();
	if (fd < 0 || fd >= FDCOUNT_LIMIT) return NULL;
	return curr->fdTable[fd];
}

void remove_file_from_fdt(int fd) {
	struct thread *curr = thread_current();
	if (fd < 0 || fd >= FDCOUNT_LIMIT) return;
	curr->fdTable[fd] = NULL;
}
/*----------------------------helper function end------------------------------*/

int open(const char *file) {
	check_address(file);
	lock_acquire(&file_rw_lock);
    struct file *fileobj = filesys_open(file);

    if (fileobj == NULL) {
        return -1;
    }

    int fd = add_file_to_fdt(fileobj);

    if (fd == -1) {
        file_close(fileobj);
    }
	lock_release(&file_rw_lock);
	return fd;
}

void close(int fd) {
	if (fd < 2) return;
	struct file *fileobj = fd_to_struct_file(fd);
	if (fileobj == NULL) return;
	remove_file_from_fdt(fd);
	file_close(fileobj);
}

int filesize(int fd) {
	struct file *fileobj = fd_to_struct_file(fd);
	if (fileobj == NULL) return -1;
	return file_length(fileobj);
}

int read(int fd, void *buffer, unsigned size) {
	check_address(buffer);
	int ret;
	struct file *fileobj = fd_to_struct_file(fd);

	if (fileobj == NULL) return -1;
	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
		return NULL;
	}
	if (fileobj == STDIN) {
		int i;
		char c;
		unsigned char *buf = buffer;
		
		/* 키보드로 적은(버퍼) 내용 받아옴 */
		for (i = 0; i < size; i++) {
			c = input_getc();
			*buf++ = c;
			if (c == '\0')
				break;
		}
		ret = i;
	} else if (fileobj == STDOUT) {
		ret = -1;
	} else {
		lock_acquire(&file_rw_lock);
		ret = file_read(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}
	return ret;
}

int write(int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	struct file *fileobj = fd_to_struct_file(fd);
	int read_count;
	if (fileobj == NULL) return -1;
	
	if (fileobj == STDOUT) {
		putbuf(buffer, size);
		read_count = size;
	}	
	else if (fileobj == STDIN) {
		return -1;
	} else {
		lock_acquire(&file_rw_lock);
		read_count = file_write(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}
	return read_count; // ! 추가
}

void seek(int fd, unsigned position) {
	if (fd < 2) return;
	struct file *fileobj = fd_to_struct_file(fd);
	// if (fileobj == NULL) return;
	file_seek(fileobj, position);
}

unsigned tell(int fd) {
	if (fd < 2) return;
	struct file *fileobj = fd_to_struct_file(fd);
	// if (fileobj == NULL) return;
	return file_tell(fileobj);
}