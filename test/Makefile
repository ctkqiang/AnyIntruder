CC = gcc
CFLAGS = -I. -I../includes $(shell pkg-config --cflags libcurl openssl json-c libpcap)
LIBS = $(shell pkg-config --libs libcurl openssl json-c libpcap) -lncurses

UNITY_SRC = unity.c
TEST_SRC = test_webhook.c test_monitor.c test_http_client.c

all: test_webhook test_monitor test_http_client

test_webhook: $(UNITY_SRC) test_webhook.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

test_monitor: $(UNITY_SRC) test_monitor.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

test_http_client: $(UNITY_SRC) test_http_client.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f test_webhook test_monitor test_http_client *.o