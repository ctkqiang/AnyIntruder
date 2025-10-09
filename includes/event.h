#include <cstdint>
#include <time.h>

typedef struct Event {
    char src_ip[64];
    uint16_t dst_port;
    char summary[256]; 
    time_t ts;
} Event;