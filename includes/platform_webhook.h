#pragma once

#ifndef PLATFORM_WEBHOOK_H
#define PLATFORM_WEBHOOK_H

#include "platform.h"

int webhook_send(Platform platform, const char *url, const char *json);

#endif
