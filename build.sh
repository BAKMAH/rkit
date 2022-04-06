gcc \
-fPIC \
-shared \
-D_GNU_SOURCE \
-o rkit.so \
src/anti.c \
src/rkit.c \
src/utils.c \
src/hooks.c \
-lpthread -ldl -w
