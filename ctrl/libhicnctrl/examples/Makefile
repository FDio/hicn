SHELL   := /bin/bash

CC       = gcc

CFLAGS   = -std=gnu11 -g -Wall -Wextra -Wpedantic -Wstrict-aliasing -DWITH_POLICY=1
LDFLAGS  = -lhicnctrl -lhicn

# Android
#CFLAGS  += -I../includes -I../../../lib/includes -L../../../build/build-root/lib
#LDFLAGS += -lm -llog

SRC      = $(wildcard *.c)
EXEC     = $(SRC:.c=)

all: $(EXEC)

%:%.c
	@$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

.PHONY: clean mrproper

clean:
	@rm -rf $(EXEC)

mrproper: clean
