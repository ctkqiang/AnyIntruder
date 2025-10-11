#pragma once

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stdio.h>

#include "header.h"
#include "http_request.h"
#include "http_response.h"

void http_add_header(HttpRequest *req, const char *name, const char *value);

void http_free_request(HttpRequest *req);

void http_free_response(HttpResponse *res);

int http_perform(HttpRequest *req, HttpResponse *res);

#endif