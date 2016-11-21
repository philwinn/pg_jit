MODULE_big = pg_jit
OBJS = pg_jit.o
EXTENSION = pg_jit

FIRM_LIBS = -lfirm -lm -ldl

override CFLAGS += -Wall -O3 -march=native -fomit-frame-pointer -std=gnu99

ifdef DEBUG
COPT		+= -O0
CXXFLAGS	+= -g -O0
endif

ifndef PG_CONFIG
PG_CONFIG = pg_config
endif

SHLIB_LINK += $(FIRM_LIBS)

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
