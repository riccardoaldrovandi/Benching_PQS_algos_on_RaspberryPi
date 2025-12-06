CC = gcc

CFLAGS = -O3 -std=c11 -Wall -Wextra -D_GNU_SOURCE \
         -Iinclude \
         -Isrc \
         -Ithird_party/ascon/crypto_hash/asconhash256/opt32 \
         -Ithird_party/ascon/crypto_aead/asconaead128/opt32

LDFLAGS = -L/usr/local/lib -L/usr/local/lib -lcrypto -lm -lpapi -loqs

SRC = \
    src/bench_main.c \
    src/bench_hash.c \
    src/bench_keygen.c \
    src/bench_sign.c \
    src/bench_verify.c \
    src/bench_enc.c \
    src/bench_dec.c \
    src/bench_kem_common.c \
    src/bench_kem_keygen.c \
    src/bench_kem_encaps.c \
    src/bench_kem_decaps.c \
    src/bench_kdf.c \
    src/benching.c \
    src/util_csv.c \
    src/profiling.c \
    src/papi_util.c \
    third_party/ascon/crypto_hash/asconhash256/opt64/hash.c \
    third_party/ascon/crypto_hash/asconhash256/opt64/permutations.c \
    third_party/ascon/crypto_aead/asconaead128/opt64/aead.c \
    third_party/ascon/crypto_aead/asconaead128/opt64/permutations.c \
    third_party/ascon/crypto_aead/asconaead128/opt64/printstate.c

OBJ = $(SRC:.c=.o)

BIN = pqc_bench

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

dep:
	@echo "Updating dependencies..."
	@$(CC) -MM $(SRC) > .depend

-include .depend
