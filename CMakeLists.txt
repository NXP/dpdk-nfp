CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(socket)

SET(CMAKE_C_FLAGS_RELEASE "$ENV{CFLAGS} -O2 -Wall -Werror -Winvalid-pch -Wextra -Wcast-qual -Wdeprecated -Wformat -Wformat-nonliteral -Wformat-security -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wold-style-definition -Wpointer-arith -Wsign-compare -Wstrict-prototypes -Wundef -Wwrite-strings -Wno-address-of-packed-member -Wno-packed-not-aligned -Wno-missing-field-initializers -Wno-zero-length-bounds -Wno-format-truncation")
# CMakeLists.txt

set(CMAKE_SYSTEM_NAME Linux)

ADD_SUBDIRECTORY(lib)
