#pragma once

#ifndef PLATFORM_H
#define PLATFORM_H

typedef enum Platform {
    PLATFORM_SLACK,
    PLATFORM_DISCORD,
    PLATFORM_MSTEAMS,
    PLATFORM_DINGTALK,
    PLATFORM_WECHAT,
    PLATFORM_FEISHU
} Platform;

#endif