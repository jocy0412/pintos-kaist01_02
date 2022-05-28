#include "../lib/stdbool.h"
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
    
void check_address(void *);             /* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 잘못된 접근일 결우 프로세스 종료 */
void get_argument(void *, int *, int);  /* 유저 스택에 저장된 인자값들을 커널로 저장, 인자가 저장된 위치가 유저영역인지 확인 */

/* 시스템 콜 */
void halt(void);                        /* pintos를 종료시키는 시스템 콜 */
void exit(int);                         /* 현재 프로세스를 종료시키는 시스템 콜 */
bool create(const char *, unsigned);    /* 파일을 생성하는 시스템 콜 */
bool remove(const char *);              /* 파일을 삭제하는 시스템 콜 */


#endif /* userprog/syscall.h */
