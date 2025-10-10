#pragma once

#include <stdint.h>

#ifndef EVENT_H
#define EVENT_H

#include <time.h>

typedef struct Event {
    char src_ip[64];
    uint16_t dst_port;
    char summary[256]; 
    time_t ts;
} Event;

#endif