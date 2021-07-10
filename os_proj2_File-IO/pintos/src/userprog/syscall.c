#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "process.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/string.h"

static void syscall_handler (struct intr_frame *);
void ifuser(void* p);
void ifnull(void* p);

struct file
{
	struct inode* inode;
	off_t pos;
	bool  deny_write;
};

struct lock filesys_lock;
struct lock mutex_lock;
uint32_t readCount;


void ifuser(void* p)
{
	if(!is_user_vaddr(p))
		exit(-1);
}

void ifnull(void* p)
{
	if(p == NULL)
		exit(-1);
}

	void
syscall_init (void) 
{
	// addition 2
	readCount = 0;
	lock_init(&mutex_lock);
	lock_init(&filesys_lock);

	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

	static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	void* tesp = f->esp;

	switch(*(uint32_t*)tesp)
	{
		case SYS_HALT:
			halt();
			break;
		
		case SYS_EXIT:
			ifuser(tesp + 4);
			exit(*(int*)(f->esp + 4));
			break;
		
		case SYS_EXEC:
			ifuser(f->esp + 4);
			f->eax = exec((const char *)*(uint32_t*)(f->esp + 4));
			break;
		
		case SYS_WAIT:
			ifuser(tesp + 4);
			f->eax = wait((pid_t)*(uint32_t*)(f->esp + 4));
			break;
		
		case SYS_CREATE:
			ifuser(tesp + 4);
			ifuser(tesp + 8);
			f->eax = create((const char*)*(uint32_t *)(f->esp + 4),
					(unsigned)*(uint32_t*)(f->esp + 8));
			break;
		
		case SYS_REMOVE:
			ifuser(tesp + 4);
			f->eax = remove((const char*)*(uint32_t *)(f->esp + 4));
			break;
		
		case SYS_OPEN:
			ifuser(tesp + 4);
			f->eax = open((const char*)*(uint32_t *)(f->esp + 4));
			break;
		
		case SYS_FILESIZE:
			ifuser(tesp + 4);
			f->eax = filesize((int)*(uint32_t*)(f->esp + 4));
			break;

		case SYS_READ:
			ifuser(tesp + 4);
			ifuser(tesp + 8);
			ifuser(tesp + 12);
			f->eax = read((int)*(uint32_t*)(f->esp +4),
					(void*)*(uint32_t*)(f->esp + 8),
					(unsigned)*(uint32_t*)(f->esp + 12));
			break;

		case SYS_WRITE:
			ifuser(tesp + 4);
			ifuser(tesp + 8);
			ifuser(tesp + 12);
			f->eax = write((int)*(uint32_t*)(f->esp + 4),
					(void*)*(uint32_t*)(f->esp + 8),
					(unsigned)*(uint32_t*)(f->esp + 12));
			break;

		case SYS_SEEK:
			ifuser(tesp + 4);
			ifuser(tesp + 8);
			seek((int)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
			break;

		case SYS_TELL:
			ifuser(tesp + 4);
			f->eax = tell((int)*(uint32_t *)(f->esp + 4));
			break;

		case SYS_CLOSE:
			ifuser(tesp + 4);
			close((int)*(uint32_t *)(f->esp + 4));
			break;
	}

}

void halt(void)
{
	shutdown_power_off();
}

void exit(int status)
{
	// return status to kernel

	printf("%s: exit(%d)\n", thread_name(), status);
 	thread_current()->exit_status = status;
	
	for(int i = 3; i < 128; i++)
		if(thread_current()->fd[i] != NULL)
			close(i);

	thread_exit();
}	

pid_t exec(const char *file)
{
	return process_execute(file);
}


int wait(pid_t pid)
{
	// check valid process (pid)
	return process_wait(pid);
}

bool create(const char *file, unsigned initial_size)
{
	ifnull((void*)file);

	return filesys_create(file, initial_size);
}

bool remove(const char* file)
{
	ifnull((void*)file);

	return filesys_remove(file);	
}

int open(const char* file)
{
	ifnull((void*)file);
	ifuser((void*)file);

	// can read multiple
	lock_acquire(&mutex_lock);

	readCount++;
	if(readCount == 1)
		lock_acquire(&filesys_lock);

	lock_release(&mutex_lock);

	int ret = -1;
	struct file* fp = filesys_open(file);

	if(fp == NULL)
		ret = -1;
	else
		for(int i= 3; i<128; i++)
			if(thread_current()->fd[i] == NULL)
			{
				if(strcmp(thread_current()->name, file) == 0)
					file_deny_write(fp);

				thread_current()->fd[i] = fp;
				
				ret = i;
				break;
			}
	
	lock_acquire(&mutex_lock);

	readCount--;
	if(readCount == 0)
		lock_release(&filesys_lock);

	lock_release(&mutex_lock);

	return ret;
}

int filesize(int fd)
{
	ifnull(thread_current()->fd[fd]);

	return file_length(thread_current()->fd[fd]);
}

int read(int fd, void *buffer, unsigned length)
{
	ifuser(buffer);
	
	lock_acquire(&mutex_lock);

	int i = 0;
	readCount++;
	if(readCount == 1)
		lock_acquire(&filesys_lock);

	lock_release(&mutex_lock);

	if(fd == 0)
		for(i = 0; i < (int)length; i++)
		{
			((char*)buffer)[i] = input_getc();

			if(((char *)buffer)[i] == '\0') break;
		}

	else if(fd > 2)
	{
		if(thread_current()->fd[fd] == NULL)
			exit(-1);
		else
			i = file_read(thread_current()->fd[fd], buffer, length);
	}

	lock_acquire(&mutex_lock);

	readCount--;
	if(readCount == 0)
		lock_release(&filesys_lock);

	lock_release(&mutex_lock);

	return i;
}

int write(int fd, const void* buffer, unsigned length)
{
	lock_acquire(&filesys_lock);
	int ret = -1;

	if(fd == 1)
	{
		putbuf(buffer, length);
		ret = length;
	}
	else if(fd > 2)
	{
		if(thread_current()->fd[fd] == NULL)
			exit(-1);

		if(thread_current()->fd[fd]->deny_write)
			file_deny_write(thread_current()->fd[fd]);

		ret = file_write(thread_current()->fd[fd], buffer, length);
	}
	lock_release(&filesys_lock);

	return ret;
}


void seek(int fd, unsigned position)
{
	if(thread_current()->fd[fd] == NULL)
	{
		exit(-1);
	}
	file_seek(thread_current()->fd[fd], position);
}


unsigned tell(int fd)
{
	if(thread_current()->fd[fd] == NULL)
	{
		exit(-1);
	}
	return file_tell(thread_current()->fd[fd]);
}


void close (int fd)
{
	if(thread_current()->fd[fd] == NULL)
	{
		exit(-1);
	}
	struct file* fp = thread_current()->fd[fd];
	thread_current()->fd[fd] = NULL;
	file_close(fp);
}

