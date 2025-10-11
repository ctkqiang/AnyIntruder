#pragma once

#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include <stdio.h>
#include "header.h"

typedef struct {
    int status_code;
    char *status_msg;
    Header headers[MAX_HEADERS];
    int header_count;
    char *body;        
    size_t body_len;
} HttpResponse;

#endif
