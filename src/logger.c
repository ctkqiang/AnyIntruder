#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "../includes/attacker.h"
#include "../includes/logger.h"
#include "../includes/config.h"

static FILE *logf = NULL;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

int logger_init(const char *path) {
    logf = fopen(path ? path : LOG_FILE, "a");
    if (!logf) return -1;
    return 0;
}

static void ts_now(char *buf, size_t n) {
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, n, "%Y-%m-%d %H:%M:%S", &tm);
}

void logger_log_event(const Event *e) {
    if (!logf) return;
    char ts[64];
    ts_now(ts, sizeof(ts));
    pthread_mutex_lock(&log_lock);
    fprintf(logf, "[%s] %s -> port %u : %s\n", ts, e->src_ip, e->dst_port, e->summary);
    fflush(logf);
    pthread_mutex_unlock(&log_lock);
}

void logger_log_attacker(const Attacker *a) {
    if (!logf || !a) return;
    char ts[0x40];

    ts_now(ts, sizeof(ts));

    pthread_mutex_lock(&log_lock);

    fprintf(logf, "[%s] ATTACKER %s total=%lu last_seen=%ld\n", ts, a->ip, (unsigned long)a->total_hits, (long)a->last_seen);
    fflush(logf);

    pthread_mutex_unlock(&log_lock);
}

void logger_shutdown(void) {
    if (logf) {
        fclose(logf);
        logf = NULL;
    }
}
