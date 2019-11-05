EXEC     = $(shell basename $$(pwd))
CC       = gcc

CFLAGS   = -std=gnu11 -O3 -Wall -Wextra -Wpedantic -Wstrict-aliasing -DWITH_POLICY=1
LDFLAGS  = -lhicn -lhicnctrl

SRC      = $(wildcard *.c)
EXEC     = $(SRC:.c=)

all: $(EXEC)

${EXEC}: $(SRC)
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

.PHONY: clean mrproper

clean:
	@rm -rf $(EXEC)

mrproper: clean
