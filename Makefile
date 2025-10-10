CC := gcc
PKG := pkg-config
TARGET := anyintruder
SRCS := any_intruder.c src/monitor.c src/logger.c src/ui.c
OBJS := $(SRCS:.c=.o)

BREW_PCAP := $(shell command -v brew >/dev/null 2>&1 && brew --prefix libpcap 2>/dev/null || echo)
ifeq ($(BREW_PCAP),)
PKG_CONFIG_PATH :=
else
PKG_CONFIG_PATH := $(BREW_PCAP)/lib/pkgconfig:$(PKG_CONFIG_PATH)
export PKG_CONFIG_PATH
endif

PCAP_CFLAGS := $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" $(PKG) --cflags libpcap 2>/dev/null || echo)
PCAP_LIBS   := $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" $(PKG) --libs libpcap 2>/dev/null || echo)
NCURSES_CFLAGS := $(shell $(PKG) --cflags ncurses 2>/dev/null || echo)
NCURSES_LIBS   := $(shell $(PKG) --libs ncurses 2>/dev/null || echo)

CFLAGS := -Wall -O2 -Iinclude -pthread $(PCAP_CFLAGS) $(NCURSES_CFLAGS)
LIBS := $(PCAP_LIBS) $(NCURSES_LIBS)

ifeq ($(strip $(LIBS)),)
LIBS := -lpcap -lncurses
endif

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

run: all
	./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
