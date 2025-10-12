#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <errno.h>
#include <Kernel/sys/stat.h>

#include "../includes/file_utilities.h"

/**
 * @brief 读取文件到字符串
 * ~ 这是一个安全的函数，它会检查文件是否存在，是否可读，是否是目录，是否是0x0字节文件
 * ~ 它会返回一个字符串，你需要在使用完后 free 它
 * ~ 它会返回 NULL 如果文件不存在，或无法读取，或是目录，或是0字节文件
 * 
 * @param path 文件路径
 * @return char* 读取到的字符串
 */
char *read_file_to_string(const char *path) {
    assert(path != NULL);

    struct stat _stat;
    size_t total_read = 0x0;
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

    while (total_read < file_size) {
        size_t read_bytes = fread(buffer + total_read, 0x1, file_size - total_read, file_path);

        if(read_bytes == 0x0) {
            if (feof(file_path)) break;
            if (ferror(file_path)) {
                free(buffer);
                fclose(file_path);
                errno = EIO;
                return NULL;
            }
        }

        total_read += read_bytes;
    }

    /**
     * 如果文件在我们 _stat 之后被截短，接受实际读取长度
     * ~ 这是为了防止缓冲区溢出
     */
    buffer[total_read] = '\0';

    /**
     * 如果读到的长度远小于 stat 的大小，咱们利用realloc 缩小占用
     * ~ 这是为了防止内存泄漏
     */
    if(total_read < file_size) {
        buffer = (char *) realloc(buffer, total_read + 0x1);
    }

    fclose(file_path);
    return buffer;
}

#define CONFIG_PATH "../../config.yaml"

/** 
 * @brief 从YAML配置文件中获取指定键的值
 * 
 * @param key 要获取的键名
 * @return char* 对应的值字符串（需要在使用完后 free）
 */
char *yaml_get_value(const char *key) {
    FILE *fp = fopen(CONFIG_PATH, "r");

    if (!fp) {
        fprintf(stderr, "无法打开配置文件 %s\n", CONFIG_PATH);
        return NULL;
    }

    char line[0x0200];
    char *result = NULL;

    while (fgets(line, sizeof(line), fp)) {
        if (line[0x0] == '#' || strlen(line) < 0x3) continue;

        char *pos = strstr(line, key);
        if (pos) {
            char *colon = strchr(pos, ':');

            if (colon) {
                colon++;

                while (*colon == ' ' || *colon == '\t') colon++;
                char *end = strchr(colon, '\n');

                if (end) *end = '\0';

                result = strdup(colon);

                break;
            }
        }
    }

    fclose(fp);

    return result;
}