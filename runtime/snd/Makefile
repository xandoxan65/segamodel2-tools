# Stand-alone Model 2A sound UART (i8251 / MIDI) HLE library.
#
#   make                  # build/libmodel2_snd.a
#   make clean
#   PREFIX=... make install
#
# No lift / SDL / GL required. Inject MIDI consumers via
# model2_snd_bind_host().

SHELL := /bin/bash
.DELETE_ON_ERROR:

SND_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD    ?= $(SND_ROOT)/build
LIB      := $(BUILD)/libmodel2_snd.a

CC ?= cc
AR ?= ar

CFLAGS ?= -std=c99 -Wall -Wextra -Wno-unused-parameter -O2
override CFLAGS += -I$(SND_ROOT)/include

SRCS := $(wildcard $(SND_ROOT)/*.c)
OBJS := $(patsubst $(SND_ROOT)/%.c,$(BUILD)/%.o,$(SRCS))

.PHONY: all clean install help

all: $(LIB)

help:
	@echo "Targets:"
	@echo "  make          — $(LIB)"
	@echo "  make clean    — remove $(BUILD)/"
	@echo "  make install  — copy lib + headers to PREFIX (default /usr/local)"

$(LIB): $(OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $(OBJS)

$(BUILD)/%.o: $(SND_ROOT)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

PREFIX ?= /usr/local
install: $(LIB)
	install -d $(PREFIX)/lib $(PREFIX)/include/model2_snd
	install -m 644 $(LIB) $(PREFIX)/lib/
	install -m 644 $(SND_ROOT)/include/*.h $(PREFIX)/include/model2_snd/

clean:
	rm -rf $(BUILD)
