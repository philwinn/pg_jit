-include config.mak

VARIANT 	?= DEBUG
PREFIX		?= /usr/local

MODULE_big 	= pg_jit
OBJS		= pg_jit.o
EXTENSION	= pg_jit
LFLAGS		= -lfirm -lm -ldl

# Variants
CFLAGS_DEBUG	= -O0 -g3
CFLAGS_OPTIMIZE = -O3 -fomit-frame-pointer 

override CFLAGS	+= $(CFLAGS_$(VARIANT)) -Wall -std=gnu99 -march=native -I$(PREFIX)/include -L$(PREFIX)/lib

SHLIB_LINK	+= $(LFLAGS)

PG_CONFIG 	= $(PREFIX)/bin/pg_config
PGXS 		:= $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
