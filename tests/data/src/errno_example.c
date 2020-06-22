#include <errno.h>
#include <stdio.h>

extern int errno;

int main() {
  FILE* f;
  f = fopen("badfilename", "r");
  if (f == NULL) {
    printf("Errno: %d\n", errno);
  } else {
    fclose(f);
  }
  return 0;
}
