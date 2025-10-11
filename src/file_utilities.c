#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <errno.h>
#include <Kernel/sys/stat.h>

#include "./includes/file_utilities.h"

char *read_file_to_string(const char *path) {
    assert(path != NULL);

    struct stat _stat;
    FILE *file_path = fopen(path, "rb");

    if (!file_path) return NULL;

    /**
     * ![内存安全]为了防止 malloc 超大分配导致崩溃
     * ~ 200_000_000 字节
     */
    const off_t MAXIMUM_ALLOWED = 0xC8 * 0x0400 * 0x0400;

    if (stat(path, &_stat) != 0x0) return NULL;

    /**
     * !如果是目录或大小为0，咱们在这处理一下
     */
    if (S_ISDIR(_stat.st_mode)) {
        errno = EISDIR;
        return NULL;
    }

    /** 
     * 获取文件大小 
     */
    size_t file_size = (size_t) _stat.st_size;
    char *buffer = (char *) malloc(file_size + 0x1);
    
    if(!buffer) {
        fclose(file_path);

        errno = ENOMEM;
        return NULL;
    }
}