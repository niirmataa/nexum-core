CC ?= cc

CFLAGS ?= -O2 -Wall -Wextra -Wpedantic
CFLAGS += -Isrc -Ivendor/falcon
LDFLAGS ?=
BIN ?= nexum

HARDEN_CFLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE \
	-Wformat -Wformat-security -Werror=format-security
HARDEN_LDFLAGS = -Wl,-z,relro,-z,now -pie -Wl,-z,noexecstack

CFLAGS += $(HARDEN_CFLAGS)
LDFLAGS += $(HARDEN_LDFLAGS)

# On Alpine you likely want: apk add build-base libsodium-dev curl-dev oqs-dev sqlite-dev
LIBS = -lsodium -lcurl -loqs -ljansson -lsqlite3 -lm

FALCON_SRC = \
	vendor/falcon/falcon-enc.c \
	vendor/falcon/falcon-fft.c \
	vendor/falcon/falcon-keygen.c \
	vendor/falcon/falcon-sign.c \
	vendor/falcon/falcon-vrfy.c \
	vendor/falcon/frng.c \
	vendor/falcon/shake.c

SRC = \
	src/util.c \
	src/vault.c \
	src/json_min.c \
	src/auth.c \
	src/pow.c \
	src/pqc_falcon.c \
	src/pqc_kem.c \
	src/dm.c \
	src/prekeys.c \
	src/cli_common.c \
	src/cli_config.c \
	src/cli_auth_core_cmds.c \
	src/cli_ext_cmds.c \
	src/http.c \
	src/cli_app.c \
	src/main.c

OBJ = $(FALCON_SRC:.c=.o) $(SRC:.c=.o)

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

clean:
	rm -f $(BIN) $(OBJ)

.PHONY: all clean
