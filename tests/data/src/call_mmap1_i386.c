#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

struct mmap_arg_struct32 {
  unsigned int addr;
  unsigned int len;
  unsigned int prot;
  unsigned int flags;
  unsigned int fd;
  unsigned int offset;
};

int main(void) {
  struct mmap_arg_struct32 arg = {0, 4096, 0x7, 0x22, 0, 0};
  struct mmap_arg_struct32 *arg_ptr;
  arg_ptr = &arg;
  // int rc = syscall(0xc0, 0, 4096, 0x7, 0x22, -1, 0);
  int rc = syscall(0x5a, arg_ptr);  // i386 mmap1
  if (rc == -1) printf("mmap failed, errno = %d\n", errno);

  return 0;
}
