#include <pthread.h>
#include <stdio.h>

void *inc_x(void *x){
    int *x_ptr = (int *)x;
    ++(*x_ptr);
    printf("x increment finished\n");
    return NULL;
}

int main(){
    int x = 0, y = 0;
    printf("x: %d, y: %d\n", x, y);
    pthread_t inc_x_thread;
    if(pthread_create(&inc_x_thread, NULL, inc_x, &x)) {
        fprintf(stderr, "Error creating thread\n");
        return 1;
    }
    ++y;
    printf("y increment finished\n");
    if(pthread_join(inc_x_thread, NULL)) {
        fprintf(stderr, "Error joining thread\n");
        return 2;
    }
    printf("x: %d, y: %d\n", x, y);
    return 0;
}
