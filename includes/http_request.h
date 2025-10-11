#pragma once

#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include <stdio.h>
#include "header.h"

typedef struct {
    char *method;      
    char *host;     
    char *port;        
    char *path;        
    Header headers[MAX_HEADERS];
    int header_count;
    char *body;        
    size_t body_len;
} HttpRequest;

#endif