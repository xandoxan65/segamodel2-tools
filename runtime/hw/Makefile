# Stand-alone Model 2 GEO MMIO + vsync hardware library.
# TGP/copro HLE lives in ../tgp (libmodel2_tgp.a); this lib owns PRG FIFO +
# routes 0x00884000..0x00887FFF to model2_tgp_* under g_fifo_mtx.
#
#   make                  # build/libmodel2_hw.a
#   make clean
#   PREFIX=... make install
#
# No uplifted game / lift ROM required. Inject board + display via
# model2_hw_bind_host() (also binds TGP host). Link with libmodel2_tgp,
# -lpthread -lm.

SHELL := /bin/bash
.DELETE_ON_ERROR:

HW_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD   ?= $(HW_ROOT)/build
LIB     := $(BUILD)/libmodel2_hw.a

CC ?= cc
AR ?= ar

CFLAGS ?= -std=c99 -Wall -Wextra -Wno-unused-parameter -O2
override CFLAGS += -I$(HW_ROOT)/include -I$(HW_ROOT)/../tgp/include -I$(HW_ROOT)/../include

SRCS := $(wildcard $(HW_ROOT)/*.c)
OBJS := $(patsubst $(HW_ROOT)/%.c,$(BUILD)/%.o,$(SRCS))

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

$(BUILD)/%.o: $(HW_ROOT)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

PREFIX ?= /usr/local
install: $(LIB)
	install -d $(PREFIX)/lib $(PREFIX)/include/model2_hw
	install -m 644 $(LIB) $(PREFIX)/lib/
	install -m 644 $(HW_ROOT)/include/*.h $(PREFIX)/include/model2_hw/

clean:
	rm -rf $(BUILD)
