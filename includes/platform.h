#pragma once

#ifndef PLATFORM_H
#define PLATFORM_H

typedef enum Platform {
    PLATFORM_NONE       = 0,
    PLATFORM_SLACK      = (1 << 0),
    PLATFORM_DISCORD    = (1 << 1),
    PLATFORM_MSTEAMS    = (1 << 2),
    PLATFORM_TELEGRAM   = (1 << 3),
    PLATFORM_DINGDING   = (1 << 4),
    PLATFORM_WECHAT     = (1 << 5),
    PLATFORM_FEISHU     = (1 << 6)
} Platform;

#endif