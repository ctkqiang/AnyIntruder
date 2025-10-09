#include <cstdint>
#include <ctime>

typedef struct Attacker {
    char ip[64];
    uint64_t total_hits;
    uint64_t hits_by_port[65536 / 1024 + 1];
    time_t last_seen;
    struct Attacker *next;
} Attacker;