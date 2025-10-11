#pragma once

#ifndef TELEGRAM_H
#define TELEGRAM_H

#ifdef __cplusplus
extern "C" {
#endif
    int telegram_send_message(const char *text);

#ifdef __cplusplus
}
#endif

int telegram_send_message(const char *text);

#endif