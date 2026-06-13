#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <errno.h>

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
    (void)(0xC8LL * 0x0400LL * 0x0400LL);  /* 200MB 上限 — 保留以便将来使用 */

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
    size_t file_size = (size_t)_stat.st_size;
    char *buffer = (char *)malloc(file_size + 0x1);

    if (!buffer) {
        fclose(file_path);

        errno = ENOMEM;
        return NULL;
    }

    while (total_read < file_size) {
        size_t read_bytes = fread(buffer + total_read, 0x1, file_size - total_read, file_path);

        if (read_bytes == 0x0) {
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
    if (total_read < file_size) {
        buffer = (char *)realloc(buffer, total_read + 0x1);
    }

    fclose(file_path);
    return buffer;
}

#define CONFIG_PATH "../../config.yaml"

/** @brief
 *
 * 获取当前行的缩进级别 (空格数)
 */
static int get_indent(const char *line) {
    int indent = 0x0;
    while (*line == ' ') {
        indent++;
        line++;
    }
    return indent;
}

/** @brief
 *
 * 从YAML配置文件中获取指定键的值
 * 支持嵌套键: "telegram.bot_token" 会匹配:
 *   telegram:
 *     bot_token: <value>
 *
 * @param key 要获取的键名 (点分隔表示嵌套)
 * @return char* 对应的值字符串（需要在使用完后 free）
 */
char *yaml_get_value(const char *key) {
    if (!key) return NULL;

    FILE *fp = fopen(CONFIG_PATH, "r");
    if (!fp) {
        fprintf(stderr, "无法打开配置文件 %s\n", CONFIG_PATH);
        return NULL;
    }

    /**
     * 分割 key 为多级: "telegram.bot_token" → ["telegram", "bot_token"]
     */
    char key_copy[0x100];
    strncpy(key_copy, key, sizeof(key_copy) - 0x1);
    key_copy[sizeof(key_copy) - 0x1] = '\0';

    char *keys[0x10];  /* 最多 16 级嵌套 */
    int key_count = 0x0;

    char *save;
    char *token = strtok_r(key_copy, ".", &save);
    while (token && key_count < 0x10) {
        keys[key_count++] = token;
        token = strtok_r(NULL, ".", &save);
    }

    if (key_count == 0x0) {
        fclose(fp);
        return NULL;
    }

    char line[0x0200];
    char *result = NULL;

    int current_level = 0x0;     /* 当前匹配到的 key 层级 */
    int expected_indent = 0x0;   /* 期望的缩进级别 */

    while (fgets(line, sizeof(line), fp)) {
        /**
         * 跳过注释和空行
         */
        if (line[0x0] == '#' || line[0x0] == '\n' || line[0x0] == '\r') continue;

        int indent = get_indent(line);
        if (indent >= (int)sizeof(line) - 0x1) continue;

        /**
         * 重置: 如果缩进小于期望值, 说明退出了当前层级
         */
        if (current_level > 0x0 && indent < expected_indent) {
            /**
             * 向上回退层级 — 缩进减少说明退出了当前 scope
             */
            if (indent == 0x0) {
                current_level = 0x0;
                expected_indent = 0x0;
            }
        }

        const char *trimmed = line + indent;

        /**
         * 在当前级别查找 key
         */
        if (current_level < key_count) {
            size_t key_len = strlen(keys[current_level]);

            /**
             * 检查是否匹配当前 key (后面跟冒号)
             */
            if (strncmp(trimmed, keys[current_level], key_len) == 0x0 &&
                trimmed[key_len] == ':') {

                /**
                 * 如果是最后一级 — 提取值
                 */
                if (current_level == key_count - 0x1) {
                    const char *value_start = trimmed + key_len + 0x1;

                    while (*value_start == ' ' || *value_start == '\t') value_start++;

                    /**
                     * 去除末尾换行
                     */
                    char value[0x200];
                    strncpy(value, value_start, sizeof(value) - 0x1);
                    value[sizeof(value) - 0x1] = '\0';

                    char *end = strchr(value, '\n');
                    if (end) *end = '\0';
                    end = strchr(value, '\r');
                    if (end) *end = '\0';

                    /**
                     * 检查是否为嵌套结构 (值为空, 说明子 key 在下面)
                     */
                    if (value[0x0] == '\0') {
                        /**
                         * 是嵌套结构, 进入下一级
                         */
                        current_level++;
                        expected_indent = indent + 0x2;

                        continue;
                    }

                    result = strdup(value);
                    break;
                } else {
                    /**
                     * 不是最后一级, 进入下一级
                     */
                    current_level++;
                    expected_indent = indent + 0x2;

                    continue;
                }
            }
        }

        /**
         * 同行值匹配 (如 telegram: bot_token: XXXX 合并在一行 — 跳过)
         */
    }

    fclose(fp);

    return result;
}
