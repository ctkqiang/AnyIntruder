#ifndef HEADER_H
#define HEADER_H

#define MAX_HEADERS 0x40

typedef struct {
    char *name;
    char *value;
} Header;

#endif