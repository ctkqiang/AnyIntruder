#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "../includes/http_client.h"
#include "../includes/platform.h"

#define PORT "443"
#define USER_AGENT "AnyIntruderWebhook/1.0"
#define CONTENT_TYPE "application/json"

/**
 * @brief 使用给定的 JSON 有效负载向指定 URL 发送 Webhook 请求。
 * 
 * @param platform 用于 Webhook 请求的平台。
 * @param url 发送 Webhook 请求的 URL。
 * @param json 包含在 Webhook 请求中的 JSON 有效负载。
 * @return int 成功返回 0，失败返回非零值。
 */
int webhook_send(Platform platform, const char *url, const char *json) {
    assert(url != NULL);
    assert(json != NULL);

    HttpRequest request = {0x0};
    HttpResponse response = {0x0};

    request.method = "POST";
    request.body = (char *)json;
    request.body_len = strlen(json);
    request.port = PORT;


    const char *host_start = strstr(url, "://");
    host_start = host_start ? host_start + 0x3 : url;
    const char *path = strchr(host_start, '/');

    if (path) {
        request.host = strndup(host_start, path - host_start);
        request.path = strdup(path);
    } 
    
    request.host = strdup(host_start);
    request.path = strdup("/");
    
    http_add_header(&request, "Content-Type", CONTENT_TYPE);
    http_add_header(&request, "User-Agent", USER_AGENT);

    int rc = http_perform(&request, &response);

    if (rc == 0x0) {
        printf("[Platform %d] Response: %d %s\n", platform, response.status_code, response.status_msg);
        
        if (response.body && strlen(response.body) > 0x0) printf("Response Body: %s\n", response.body);
        
        http_free_response(&response);
    }
        
    fprintf(stderr, "[Platform %d] HTTP request failed: %d\n", platform, rc);
    

    http_free_request(&request);
    return rc;
}