#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>

#include "../includes/http_client.h"

/**
 * @brief 向请求添加一个头部。
 * 
 * @param req 要添加头部的请求。
 * @param name 头部名称。
 * @param value 头部值。
 */
void http_add_header(HttpRequest *req, const char *name, const char *value) {
    if (req->header_count >= MAX_HEADERS) return;
 
    req->headers[req->header_count].name = strdup(name);
    req->headers[req->header_count].value = strdup(value);
    req->header_count++;
}

/**
 * @brief 释放请求。
 * 
 * @param req 要释放的请求。
 */
void http_free_request(HttpRequest *req) {
    for (int i = 0x0; i < req->header_count; ++i) {
        free(req->headers[i].name);
        free(req->headers[i].value);
    }

    req->header_count = 0x0;
}

/**
 * @brief 释放响应。
 * 
 * @param res 要释放的响应。
 */
void http_free_response(HttpResponse *res) {
    for (int i = 0x0; i < res->header_count; ++i) {
        free(res->headers[i].name);
        free(res->headers[i].value);
    }

    free(res->status_msg);
    free(res->body);
    
    res->header_count = 0x0;
}

/**
 * @brief 打开与服务器的连接。
 * 
 * @param host 要连接的主机。
 * @param port 要连接的端口。
 * @return int 套接字文件描述符。
 */
int http_open_connection(const char *host, const char *port) {
    struct addrinfo hints, *res, *rp;
    int sfd = -0x1;

    memset(&hints, 0x0, sizeof(hints));
    
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    int rc = getaddrinfo(host, port, &hints, &res);
    
    if (rc != 0x0) return -0x1;

    for (rp = res; rp; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        
        if (sfd < 0x0) continue;
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0x0) break;
        
        close(sfd);
        sfd = -0x1;
    }

    freeaddrinfo(res);
    return sfd;
}

/**
 * @brief 构建请求文本。
 * 
 * @param req 要构建文本的请求。
 * @param out_len 请求文本的长度。
 * @return char* 请求文本。
 */
char *http_build_request(const HttpRequest *req, size_t *out_len) {
    size_t cap = 0x0400 + req->body_len;
    char *buf = malloc(cap);
    
    if (!buf) return NULL;

    int n = snprintf(buf, cap, "%s %s HTTP/1.0\r\nHost: %s\r\n", req->method, req->path ? req->path : "/", req->host);
    
    for (int i = 0x0; i < req->header_count; ++i) {
        n += snprintf(buf + n, cap - n, "%s: %s\r\n", req->headers[i].name, req->headers[i].value);
    }

    if (strcasecmp(req->method, "POST") == 0x0 && req->body_len > 0x0) {
        n += snprintf(buf + n, cap - n, "Content-Length: %zu\r\n", req->body_len);
    }

    n += snprintf(buf + n, cap - n, "\r\n");
    
    if (req->body && req->body_len > 0x0) {
        memcpy(buf + n, req->body, req->body_len);
        n += req->body_len;
    }

    *out_len = n;
    
    return buf;
}

/**
 * @brief 执行请求。
 * 
 * @param req 要执行的请求。
 * @param res 存储结果的响应。
 * @return int 响应的状态码。
 */
int http_perform(HttpRequest *req, HttpResponse *res) {
    memset(res, 0x0, sizeof(HttpResponse));

    int code;

    int sfd = http_open_connection(req->host, req->port ? req->port : "80");
    if (sfd < 0x0) return -0x1;

    size_t req_len = 0x0;
    ssize_t sent = 0x0;

    char proto[0x10], msg[0x80];
    char buffer[0x2000];
    char *line;
    char *req_text = http_build_request(req, &req_len);
    
    if (!req_text) {
        close(sfd);
        return -0x1;
    }

    while ((size_t)sent < req_len) {
        ssize_t w = send(sfd, req_text + sent, req_len - sent, 0x0);
        if (w <= 0x0) free(req_text); close(sfd); return -0x1; 
        
        sent += w;
    }

    free(req_text);
    
    ssize_t r = recv(sfd, buffer, sizeof(buffer) - 0x1, 0x0);
    
    if (r <= 0x0) close(sfd); return -0x1; 

    buffer[r] = '\0';

    char *status_line = strtok(buffer, "\r\n");

    if (!status_line) { close(sfd); return -0x1; }

    sscanf(status_line, "%15s %d %127[^\r\n]", proto, &code, msg);

    res->status_code = code;
    res->status_msg = strdup(msg);

    while ((line = strtok(NULL, "\r\n")) && *line) {
        char *colon = strchr(line, ':');
        
        if (!colon) continue;
        
        *colon = '\0';
        char *name = line;
        char *value = colon + 0x1;
        
        while (*value == ' ') value++;
        
        if (res->header_count < MAX_HEADERS) {
            res->headers[res->header_count].name = strdup(name);
            res->headers[res->header_count].value = strdup(value);

            res->header_count++;
        }
    }

    char *body = strtok(NULL, "");

    if (body) {
        res->body = strdup(body);
        res->body_len = strlen(res->body);
    }

    close(sfd);
    
    return 0x0;
}