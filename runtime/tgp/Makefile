# Stand-alone Model 2 TGP (MB86234 / copro FIFO) HLE library.
#
#   make                  # build/libmodel2_tgp.a
#   make clean
#   PREFIX=... make install
#
# No lift / SDL / GL required. Inject workram + GEO emit via
# model2_tgp_bind_host(). Link consumers with -lm.

SHELL := /bin/bash
.DELETE_ON_ERROR:

TGP_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD    ?= $(TGP_ROOT)/build
LIB      := $(BUILD)/libmodel2_tgp.a

CC ?= cc
AR ?= ar

CFLAGS ?= -std=c99 -Wall -Wextra -Wno-unused-parameter -O2
override CFLAGS += -I$(TGP_ROOT)/include

SRCS := $(wildcard $(TGP_ROOT)/*.c)
OBJS := $(patsubst $(TGP_ROOT)/%.c,$(BUILD)/%.o,$(SRCS))

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

$(BUILD)/%.o: $(TGP_ROOT)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

PREFIX ?= /usr/local
install: $(LIB)
	install -d $(PREFIX)/lib $(PREFIX)/include/model2_tgp
	install -m 644 $(LIB) $(PREFIX)/lib/
	install -m 644 $(TGP_ROOT)/include/*.h $(PREFIX)/include/model2_tgp/

clean:
	rm -rf $(BUILD)
