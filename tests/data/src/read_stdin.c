
#include <stdio.h>
int main() {
  char buf[20];
  fgets(buf, 20, stdin);
  printf("string is: %s\n", buf);

  return 0;
}
