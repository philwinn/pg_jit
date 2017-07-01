MODULE_big = pg_jit
OBJS = pg_jit.o
EXTENSION = pg_jit
LFLAGS = -lfirm -lm -ldl

override CFLAGS += -Wall -O3 -march=native -fomit-frame-pointer -std=gnu99
CFLAGS_DEBUG = -Wall -O0 -ggdb3 -std=gnu99

SHLIB_LINK += $(LFLAGS)

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

pg_jit.o: pg_jit.c

debug: CFLAGS = $(CFLAGS_DEBUG)
debug: pg_jit.o
