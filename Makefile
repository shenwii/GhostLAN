CC ?= cc
PREFIX ?= /usr/local

SRCDIR = src
OBJDIR = obj
BINDIR = bin
PREFIX_BIN = $(PREFIX)/$(BINDIR)

BIN = $(BINDIR)/glan

CFLAGS += -Wall
LDFLAGS += -lssl -lcrypto

ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG -g -O0
else
LDFLAGS += -s -Os
endif

ifeq ($(SELECT),1)
CFLAGS += -DSELECT
endif


SOURCES = aes.c common.c crc32.c glan.c tun.c
OBJECTS = $(patsubst %.c,$(OBJDIR)/%.o,$(SOURCES))

all: $(BIN)

$(BIN): $(OBJDIR) $(BINDIR) $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	@rm -rf $(OBJDIR) $(BINDIR)

install: all $(PREFIX_BIN)
	cp -fp $(BIN) $(PREFIX_BIN)

uninstall:
	rm -rf $(PREFIX)/$(BIN)

.PHONY: all clean install uninstall
