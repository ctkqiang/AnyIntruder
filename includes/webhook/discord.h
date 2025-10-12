#pragma once

#include <stdlib.h>

#ifndef DISCORD_H
#define DISCORD_H

typedef struct {
    char *webhook_url;
} Discord;


int discord_bot_init(Discord *discord, const char *webhook_url);

int discord_bot_send(Discord *discord, const char *username, const char *message, void (*then)(void));

#endif 