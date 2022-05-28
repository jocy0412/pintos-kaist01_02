#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	
	int sys_number = f->R.rax; 
	check_address(sys_number);

	switch(sys_number) {
		// case SYS_HALT:
		// 	halt();
		// case SYS_EXIT:
		// 	exit();
		// case SYS_FORK:
		// 	fork();		
		// case SYS_EXEC:
		// 	exec();
		// case SYS_WAIT:
		// 	wait();
		// case SYS_CREATE:
		// 	create();		
		// case SYS_REMOVE:
		// 	remove();		
		// case SYS_OPEN:
		// 	open();		
		// case SYS_FILESIZE:
		// 	filesize();
		// case SYS_READ:
		// 	read();
		// case SYS_WRITE:
		// 	write();		
		// case SYS_SEEK:
		// 	seek();		
		// case SYS_TELL:
		// 	tell();		
		// case SYS_CLOSE:
		// 	close();	
	}
	printf ("system call!\n");
	thread_exit ();
}
/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 잘못된 접근일 경우 프로세스 종료 */
void check_address(void *addr) {
	if (!is_user_vaddr(addr) || addr == NULL) {
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
	printf("%s: exit(%d)", curr->name, status);
	thread_exit();
}

/* 파일을 생성하는 시스템 콜 */                        
bool create(const char *file, unsigned initial_size) {
	if (filesys_create(file, initial_size)) {
		return true;
	}
	else {
		return false;
	}
}

/* 파일을 삭제하는 시스템 콜 */    
bool remove(const char *file) {
	if (filesys_remove(file)) {
		return true;
	} else {
		return false;
	}
}          