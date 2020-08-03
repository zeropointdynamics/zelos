#include <stdio.h>

int main(int args, char** argv) {
  void* heap = (void*)malloc(32);
  memset(heap, 'A', 64);
  printf("%s\n", heap);
  free(heap);
  heap = NULL;
  return 0;
}
