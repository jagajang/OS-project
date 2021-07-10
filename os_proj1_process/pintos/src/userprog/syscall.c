#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"


static void syscall_handler (struct intr_frame *);

void ifuser(void* p)
{
	if(!is_user_vaddr(p))
		exit(-1);
}

	void
syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

	static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	void* tesp = f->esp;

	//hex_dump(tesp, tesp, 100, 1);

	switch(*(uint32_t*)(tesp))
	{
		case SYS_HALT:
			halt();
			break;

		case SYS_EXIT:
			ifuser(tesp + 4);
			exit(*(int*)(tesp + 4));
			break;

		case SYS_EXEC:
			ifuser(tesp + 4);
			f->eax = (uint32_t)exec((const char*) *(char**)(tesp + 4));
			break;

		case SYS_WAIT:
			ifuser(tesp + 4);
			f->eax = wait(*(pid_t*)(f->esp + 4));
			break;

		case SYS_CREATE:
			break;

		case SYS_REMOVE:
			break;

		case SYS_OPEN:
			break;

		case SYS_FILESIZE:
			break;

		case SYS_READ:
			ifuser(tesp + 12);
			f->eax = (uint32_t)read(*(int*)(tesp+4), *(void**)(tesp+8),
					*(unsigned*)(tesp+12));
			break;

		case SYS_WRITE:
			ifuser(tesp + 12);
			f->eax = (uint32_t)write(*(int*)(tesp+4), *(void**)(tesp+8),
					*(unsigned*)(tesp+12));
			break;

			// sys seek
			// sys tell
			// sys close
	}

	//printf ("system call!\n");
}

void halt ()
{
	shutdown_power_off();
}

void exit (int status)
{
	// return status to kernel

	printf("%s: exit(%d)\n", thread_name(), status);
	thread_current()->exit_status = status;
	thread_exit();
}

pid_t exec (const char* file)
{
	return process_execute(file);
}

int wait (pid_t pid)
{
	// check valid process (pid)
	return process_wait(pid);
}

//bool create (const char* file, unsigned initial_size)

//bool remove

//int open

//int filesize

int read(int fd, void* buffer, unsigned length)
{
	//ifuser(buffer + length);

	unsigned i;
	for(i = 0; i < length; i++)
	{
		((char*)buffer)[i] = input_getc();

		if(((char*)buffer)[i] == '\0') break;
	}

	return (int)i;
}

int write(int fd, const void* buffer, unsigned length)
{
	ifuser((char*)buffer + length);

	if(fd == 1)
	{
		putbuf(buffer, length);
		return length;
	}

	return -1;
}

