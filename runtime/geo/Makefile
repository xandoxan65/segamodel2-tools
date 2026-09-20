# Stand-alone Model 2 geo render library.
#
#   make                  # build/libmodel2_geo.a
#   make clean
#   PREFIX=... make install
#
# No lift / i960 runtime required. Link consumers with -lpthread -lm and
# OpenGL when I960_HOST_HAVE_GL is set (default when SDL2 or GL is present).

SHELL := /bin/bash
.DELETE_ON_ERROR:

GEO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD    ?= $(GEO_ROOT)/build
LIB      := $(BUILD)/libmodel2_geo.a

CC       ?= cc
AR       ?= ar
UNAME_S  := $(shell uname -s)

PNG_CFLAGS := $(shell pkg-config --exists libpng 2>/dev/null && pkg-config --cflags libpng)
SDL_CFLAGS := $(shell pkg-config --exists sdl2 2>/dev/null && pkg-config --cflags sdl2)
ifeq ($(UNAME_S),Darwin)
  GL_CFLAGS := $(if $(shell pkg-config --exists sdl2 2>/dev/null && echo yes),-DI960_HOST_HAVE_GL,)
else
  GL_CFLAGS := $(if $(shell pkg-config --exists gl 2>/dev/null && echo yes),-DI960_HOST_HAVE_GL $(shell pkg-config --cflags gl),)
endif

CFLAGS ?= -std=c99 -Wall -Wextra -Wno-unused-parameter -O2
override CFLAGS += -I$(GEO_ROOT)/include -I$(GEO_ROOT)/../include $(PNG_CFLAGS) $(SDL_CFLAGS) $(GL_CFLAGS)

SRCS := $(wildcard $(GEO_ROOT)/*.c)
OBJS := $(patsubst $(GEO_ROOT)/%.c,$(BUILD)/%.o,$(SRCS))

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

$(BUILD)/%.o: $(GEO_ROOT)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

PREFIX ?= /usr/local
install: $(LIB)
	install -d $(PREFIX)/lib $(PREFIX)/include/model2_geo
	install -m 644 $(LIB) $(PREFIX)/lib/
	install -m 644 $(GEO_ROOT)/include/*.h $(PREFIX)/include/model2_geo/

clean:
	rm -rf $(BUILD)
