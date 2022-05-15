#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "string.h"
#define STDIN 0
#define STDOUT 1
#define STDERR 2

struct lock file_lock;

static void syscall_handler(struct intr_frame *);
/*
static int32_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
*/

void syscall_init(void)
{  
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}  

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  uint32_t *esp = f->esp;
  check_address(esp);
  uint32_t arg[3];
  //hex_dump(f->esp, f->esp, 1000, 1);
  switch (*esp)
  {
  case SYS_HALT:
    /* code */
    halt();
    break;
  case SYS_EXIT:
    get_argument(esp, arg, 1);
    exit(arg[0]);
    break;
  case SYS_WRITE:
    get_argument(esp, arg, 3);
    f->eax = write(arg[0], arg[1], arg[2]);
    break;
  case SYS_EXEC:
    get_argument(esp, arg, 1);
    f->eax = exec(arg[0]);
    break;
  case SYS_WAIT:
    get_argument(esp, arg, 1);
    f->eax = wait(arg[0]);
    break;
  case SYS_CREATE:
    get_argument(esp, arg, 2);
    check_address(arg[0]);
    f->eax = create(arg[0], arg[1]);
    break;
  case SYS_REMOVE:
    get_argument(esp, arg, 1);
    check_address(arg[0]);
    f->eax = remove(arg[0]);
    break;
  case SYS_OPEN:
    get_argument(esp, arg, 1);
    check_address(arg[0]);
    f->eax = open(arg[0]);
    break;
  case SYS_FILESIZE:
    get_argument(esp, arg, 1);
    f->eax = filesize(arg[0]);
    break;
  case SYS_READ:
    get_argument(esp, arg, 3);
    check_address(arg[1]);
    f->eax = read(arg[0], arg[1], arg[2]);
    break;
  case SYS_SEEK:
    get_argument(esp, arg, 2);
    seek(arg[0], arg[1]);
    break;
  case SYS_TELL:
    get_argument(esp, arg, 1);
    f->eax = tell(arg[0]);
    break;
  case SYS_CLOSE:
    get_argument(esp, arg, 1);
    close(arg[0]);
    break;
  default:
    //bad sc
    exit(-1);
    break;
  }

  //printf ("system call!\n");
  //thread_exit ();
}

void check_address(void *addr)
{
  if ((uint32_t)0x8048000 >= (uint32_t *)addr || (uint32_t)0xc0000000 <= (uint32_t *)addr)
  {
    //printf("Out of user memory area [0x%x]!\n", (uint32_t *)addr);
    exit(-1);
  }
}

void check_file_valid(void *addr)
{
  if (!is_user_vaddr(addr))
  {
    exit(-1);
  }
  if (pagedir_get_page(thread_current()->pagedir, addr) == NULL)
  {
    exit(-1);
  }
}

void check_file_null(void *addr)
{
  if (addr == NULL)
  {
    exit(-1);
  }
}

void get_argument(void *esp, int *arg, int count)
{
  int i = 0;
  uint32_t *base_esp = (uint32_t *)esp + 1;
  for (i = 0; i < count; i++)
  {
    check_address(base_esp);
    arg[i] = *base_esp;
    base_esp += 1;
  }
}

void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  struct thread *t = thread_current();
  t->exit = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

//pid_t exec
int exec(const char *cmd_line)
{
  return process_execute(cmd_line);
}

int wait(int pid)
{
  return process_wait(pid);
}

//bool create
int create(const char *file, unsigned initial_size)
{
  check_file_null(file);
  check_file_valid(file);

  int returnVal;

  lock_acquire(&file_lock);
  returnVal = filesys_create(file, initial_size);
  lock_release(&file_lock);

  return returnVal;
}

//bool remove
int remove(const char *file)
{
  check_file_null(file);

  int returnVal;

  lock_acquire(&file_lock);
  returnVal = filesys_remove(file);
  lock_release(&file_lock);

  return returnVal;
}

int open(const char *file)
{
  struct file *file_pointer;
  int returnVal;

  check_file_null(file);
  //check_file_valid(file);

  lock_acquire(&file_lock);
  file_pointer = filesys_open(file);
  //printf("%x\n",file_pointer);
  //printf("0x%x\n", file_pointer);
  if (file_pointer == NULL)
  {
    lock_release(&file_lock);
    return -1;
  }

  if(strcmp(file, thread_current()->name) == 0) {
    file_deny_write(file_pointer);
  }

  //printf("%x\n",file_pointer);
  //printf("%d\n",file_deny_state(file_pointer));

  returnVal = insert_file(file_pointer);
  //printf("[%d] 0x%x\n", 3, file_from_fd(3));

  lock_release(&file_lock);

  return returnVal;
}

int filesize(int fd)
{
  int returnVal;
  struct file *file_pointer = file_from_fd(fd);

  //check_file_valid(file_pointer);
  check_file_null(file_pointer);
  lock_acquire(&file_lock);
  returnVal = file_length(file_pointer);
  lock_release(&file_lock);

  return returnVal;
}

int read(int fd, void *buffer, unsigned size)
{
  //check_file_valid(file_pointer)

  int returnVal;
	lock_acquire(&file_lock);
  if (fd == STDIN)
  {
    *(uint32_t *)buffer = input_getc();
    size++;
    lock_release(&file_lock);
    return size;
  }
  else if (fd == STDOUT || fd == STDERR)
  {
    lock_release(&file_lock);
    return -1;
  }

  //lock_acquire(&file_lock); 
  struct file *file_pointer = file_from_fd(fd);
  check_file_null(file_pointer);
  returnVal = file_read(file_pointer, buffer, size);
  lock_release(&file_lock);

  return returnVal;
}

int write(int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT)
  {
    putbuf(buffer, size);
    return size;
  }

  int returnVal;
  struct file *file_pointer = file_from_fd(fd);

  lock_acquire(&file_lock);

  //check_file_valid(file_pointer);
  check_file_null(file_pointer);
  //printf("%x\n",file_pointer);
  //printf("%d\n",file_deny_state(file_pointer));
  /*
  if(file_deny_state(file_pointer) == (int)true) {
    lock_release(&file_lock);
    //exit(-1);
  }
  */

  returnVal = file_write(file_pointer, buffer, size);
  lock_release(&file_lock);

  return returnVal;
}

void seek(int fd, unsigned position)
{
  struct file *file_pointer = file_from_fd(fd);

  //check_file_valid(file_pointer);
  check_file_null(file_pointer);
  lock_acquire(&file_lock);
  file_seek(file_pointer, position);
  lock_release(&file_lock);
}

unsigned tell(int fd)
{
  struct file *file_pointer = file_from_fd(fd);

  //check_file_valid(file_pointer);
  check_file_null(file_pointer);
  return file_tell(file_from_fd(fd)) + 1;
}

void close(int fd)
{
  struct file *file_pointer = file_from_fd(fd);
  //check_file_valid(file_pointer);
  check_file_null(file_pointer);

  if (fd == STDIN || fd == STDOUT || fd == STDERR)
  {
    exit(-1);
  }

  lock_acquire(&file_lock);
  remove_file(file_pointer);
  file_close(file_pointer);
  lock_release(&file_lock);
}

/**
 * Reads a single 'byte' at user memory admemory at 'uaddr'.
 * 'uaddr' must be below PHYS_BASE.
 *
 * Returns the byte value if successful (extract the least significant byte),
 * or -1 in case of error (a segfault occurred or invalid uaddr)
 */
/*
static int32_t get_user (const uint8_t *uaddr) {
  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1;
  }

  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}
*/

/* Writes a single byte (content is 'byte') to user address 'udst'.
 * 'udst' must be below PHYS_BASE.
 *
 * Returns true if successful, false if a segfault occurred.
 */
/*
static bool put_user (uint8_t *udst, uint8_t byte) {
  if (! ((void*)udst < PHYS_BASE)) {
    return false;
  }

  int error_code;

  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}
*/
