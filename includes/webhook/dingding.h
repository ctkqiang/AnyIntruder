#pragma once

#ifndef DINGDING_H
#define DINGDING_H

#include <stdint.h>

#define _POSIX_C_SOURCE 200809L

typedef struct {
    char *DINDING_ACCESS_TOKEN;
    char *DINGDING_SECRET;
} DING_DING;

int dingding_init(DING_DING *dingding);

int dingding_send(DING_DING *dingding, const char *message, void (*then)(DING_DING *));

char *dingding_get_access_token(DING_DING *dingding);
char *dingding_get_secret(DING_DING *dingding);


#endif