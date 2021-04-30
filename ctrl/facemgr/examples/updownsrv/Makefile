EXEC     = $(shell basename $$(pwd))
CC       = gcc

CFLAGS   = -std=gnu11 -O3 -Wall -Wextra -Wpedantic -Wstrict-aliasing
#CFLAGS  += $(shell pkg-config --cflags glib-2.0 gio-2.0)
#LDFLAGS  = $(shell pkg-config --libs   glib-2.0 gio-2.0)

SRC      = $(wildcard *.c)
OBJ      = $(SRC:.c=.o)

all: $(EXEC)

${EXEC}: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean mrproper

clean:
	@rm -rf *.o

mrproper: clean
	@rm -rf $(EXEC)
