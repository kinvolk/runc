#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    int fd;
    int i = 0;
    while (1) {
        fd = openat(-1, "/dev/null2", O_RDONLY, 0);
        if (fd < 0) {
            printf("error opening file\n");
            sleep(1);
            continue;
        }

        printf("[%d] fd was: %d\n", i, fd);

        if (fd != 3) {
            printf("stopppppp. fd is not 3\n");
            getchar();
        }

        int ret = close(fd);
        if (ret) {
            printf("failed to close fd\n");
            sleep(1);
        }

        i++;
    }

    return 0;
}