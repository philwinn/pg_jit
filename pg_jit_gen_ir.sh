#!/bin/bash
# In postgres' source: Create a folder 'tmp' in src/backend/executor
# Place this script in src/backend/executor/tmp
# Neccessary preconditions:
#   install cparser (lto branch) and libFirm (lto branch),
#   comment out the following lines in src/include/pg_config.h:
#     #define HAVE__BUILTIN_UNREACHABLE 1
#     #define PG_INT128_TYPE __int128

files=(
	../execQual.c
	../../utils/adt/int.c
	../../utils/adt/int8.c
	../../utils/adt/float.c
	../../utils/adt/date.c
	../../utils/adt/datum.c
	../../utils/adt/bool.c
	../../utils/adt/numeric.c
	../../utils/fmgr/fmgr.c
	../../utils/fmgr/funcapi.c
)

for file in "${files[@]}"
do
  filename=${file%.c}
  name=$(basename "$file" ".c")
  cparser -no-integrated-cpp -w --export-ir -O0 -D_GNU_SOURCE \
		  "$filename.c" -o "$(pwd)/$name.ir" -I../../../include
done
cparser -O0 --export-ir -D_GNU_SOURCE *.ir -o executor.ir
