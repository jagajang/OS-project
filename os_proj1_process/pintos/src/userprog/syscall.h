#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

// addition
#include "lib/user/syscall.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "threads/vaddr.h"

void syscall_init (void);

// addition
void ifuser(void*);

#endif /* userprog/syscall.h */
