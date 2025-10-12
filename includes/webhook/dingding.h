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

int ding_dding_send(DING_DING *dingding, char *message, void *(then)(void));

char *dingding_get_access_token(DING_DING *dingding);
char *dingding_get_secret(DING_DING *dingding);


#endif