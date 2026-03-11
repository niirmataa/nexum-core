CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic
CFLAGS += -I../src -I../vendor/falcon -DFF_TEST_HOOKS

LIBS = -lsodium -lcurl -loqs -ljansson -lm

FALCON_SRC = \
	../vendor/falcon/codec.c \
	../vendor/falcon/common.c \
	../vendor/falcon/falcon.c \
	../vendor/falcon/fft.c \
	../vendor/falcon/fpr.c \
	../vendor/falcon/keygen.c \
	../vendor/falcon/rng.c \
	../vendor/falcon/shake.c \
	../vendor/falcon/sign.c \
	../vendor/falcon/vrfy.c

CLI_SRC = \
	../src/util.c \
	../src/vault.c \
	../src/json_min.c \
	../src/auth.c \
	../src/pow.c \
	../src/pqc_falcon.c \
	../src/pqc_kem.c \
	../src/dm.c \
	../src/prekeys.c \
	../src/http.c

all: test_kat test_cross_kat test_falcon_frodo_kat

test_kat: test_kat.c $(FALCON_SRC) $(CLI_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test_cross_kat: test_cross_kat.c $(FALCON_SRC) $(CLI_SRC) cross_kat_vectors.h
	$(CC) $(CFLAGS) -o $@ test_cross_kat.c $(FALCON_SRC) $(CLI_SRC) $(LIBS)

test_falcon_frodo_kat: test_falcon_frodo_kat.c $(FALCON_SRC) $(CLI_SRC) falcon_frodo_kat_vectors.h
	$(CC) $(CFLAGS) -o $@ test_falcon_frodo_kat.c $(FALCON_SRC) $(CLI_SRC) $(LIBS)

cross_kat_vectors.h: gen_cross_kat.py
	python3 gen_cross_kat.py > $@ 2>/dev/null

falcon_frodo_kat_vectors.h: gen_falcon_frodo_kat.py
	python3 gen_falcon_frodo_kat.py > $@

run: test_kat test_cross_kat test_falcon_frodo_kat
	./test_kat
	./test_cross_kat
	./test_falcon_frodo_kat

clean:
	rm -f test_kat test_cross_kat test_falcon_frodo_kat

.PHONY: all run clean
