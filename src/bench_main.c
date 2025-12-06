// src/bench_main.c
#include "bench_hash.h"
#include "bench_keygen.h"
#include "bench_sign.h"
#include "bench_verify.h"
#include "bench_enc.h"
#include "bench_dec.h"
#include "bench_kem_keygen.h"
#include "bench_kem_encaps.h"
#include "bench_kem_decaps.h"
#include "bench_kdf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s hash      <alg> <msg_len> <runs> <csv_path>\n"
        "  %s keygen    <alg>           <runs> <csv_path>\n"
        "  %s sign      <alg> <msg_len> <runs> <csv_path>\n"
        "  %s verify    <alg> <msg_len> <runs> <csv_path>\n"
        "  %s enc       <alg> <msg_len> <runs> <csv_path>\n"
        "  %s dec       <alg> <msg_len> <runs> <csv_path>\n"
        "  %s kemkeygen <alg>           <runs> <csv_path>\n"
        "  %s kemencaps <alg>           <runs> <csv_path>\n"
        "  %s kemdecaps <alg>           <runs> <csv_path>\n"
        "  %s kdf       <alg> <secret_len> <out_len> <runs> <csv_path>\n"
        "\n"
        "  hash <alg>      = sha256 | sha3-256 | ascon-hash256\n"
        "\n"
        "  keygen <alg>    = mldsa44 | mldsa65 | mldsa87 |\n"
        "                    falcon512 | falcon1024 | ed25519\n"
        "\n"
        "  sign/verify <alg> = mldsa44 | mldsa65 | mldsa87 |\n"
        "                      falcon512 | falcon1024 | ed25519\n"
        "\n"
        "  enc/dec <alg>   = aes256gcm | chacha20poly1305 | ascon128\n"
        "\n"
        "  kem* <alg>      = mlkem512 | mlkem768 | mlkem1024 |\n"
        "                    hqc128 | hqc192 | hqc256 |\n"
        "                    bike_l1 | bike_l3 |\n"
        "                    cm348864 | cm6688128 |\n"
        "                    ntru_hps2048509 | ntru_hps4096821 | ntru_hrss701 |\n"
        "                    sntrup761 |\n"
        "                    frodokem640aes | frodokem976aes |\n"
        "                    x25519\n"
        "\n"
        "  kdf <alg>      = hkdf_sha256 | hkdf_sha384 | hkdf_sha512 |\n"
"                   hmac_sha256 | cmac_aes256 |\n"
"                   blake2b | shake128 | shake256\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog , prog
    );
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *mode = argv[1];

    /* ---------------- HASH MODE ---------------- */
    if (strcmp(mode, "hash") == 0) {
        if (argc < 6) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        const char *alg    = argv[2];
        size_t msg_len     = (size_t)strtoul(argv[3], NULL, 10);
        int runs           = atoi(argv[4]);
        const char *csv    = argv[5];

        if (strcmp(alg, "sha256") == 0) {
            bench_sha256(msg_len, runs, csv);
        } else if (strcmp(alg, "sha3-256") == 0) {
            bench_sha3_256(msg_len, runs, csv);
        } else if (strcmp(alg, "ascon-hash256") == 0) {
            bench_ascon_hash256(msg_len, runs, csv);
        } else {
            fprintf(stderr, "Unknown hash alg: %s\n", alg);
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    /* --------------- KEYGEN (SIGNATURES) MODE --------------- */
    if (strcmp(mode, "keygen") == 0) {
        if (argc < 5) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        const char *alg = argv[2];
        int runs        = atoi(argv[3]);
        const char *csv = argv[4];

        if (strcmp(alg, "mldsa44") == 0) {
            bench_mldsa44_keygen(runs, csv);
        } else if (strcmp(alg, "mldsa65") == 0) {
            bench_mldsa65_keygen(runs, csv);
        } else if (strcmp(alg, "mldsa87") == 0) {
            bench_mldsa87_keygen(runs, csv);
        } else if (strcmp(alg, "falcon512") == 0) {
            bench_falcon512_keygen(runs, csv);
        } else if (strcmp(alg, "falcon1024") == 0) {
            bench_falcon1024_keygen(runs, csv);
        } else if (strcmp(alg, "ed25519") == 0) {
            bench_ed25519_keygen(runs, csv);
        } else {
            fprintf(stderr, "Unknown keygen alg: %s\n", alg);
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    /* --------------- SIGN MODE --------------- */
    if (strcmp(mode, "sign") == 0) {
        if (argc < 6) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        const char *alg    = argv[2];
        size_t msg_len     = (size_t)strtoul(argv[3], NULL, 10);
        int runs           = atoi(argv[4]);
        const char *csv    = argv[5];

        if (strcmp(alg, "mldsa44") == 0) {
            bench_mldsa44_sign(runs, msg_len, csv);
        } else if (strcmp(alg, "mldsa65") == 0) {
            bench_mldsa65_sign(runs, msg_len, csv);
        } else if (strcmp(alg, "mldsa87") == 0) {
            bench_mldsa87_sign(runs, msg_len, csv);
        } else if (strcmp(alg, "falcon512") == 0) {
            bench_falcon512_sign(runs, msg_len, csv);
        } else if (strcmp(alg, "falcon1024") == 0) {
            bench_falcon1024_sign(runs, msg_len, csv);
        } else if (strcmp(alg, "ed25519") == 0) {
            bench_ed25519_sign(runs, msg_len, csv);
        } else {
            fprintf(stderr, "Unknown sign alg: %s\n", alg);
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    /* --------------- VERIFY MODE --------------- */
    if (strcmp(mode, "verify") == 0) {
        if (argc < 6) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        const char *alg    = argv[2];
        size_t msg_len     = (size_t)strtoul(argv[3], NULL, 10);
        int runs           = atoi(argv[4]);
        const char *csv    = argv[5];

        if (strcmp(alg, "mldsa44") == 0) {
            bench_mldsa44_verify(runs, msg_len, csv);
        } else if (strcmp(alg, "mldsa65") == 0) {
            bench_mldsa65_verify(runs, msg_len, csv);
        } else if (strcmp(alg, "mldsa87") == 0) {
            bench_mldsa87_verify(runs, msg_len, csv);
        } else if (strcmp(alg, "falcon512") == 0) {
            bench_falcon512_verify(runs, msg_len, csv);
        } else if (strcmp(alg, "falcon1024") == 0) {
            bench_falcon1024_verify(runs, msg_len, csv);
        } else if (strcmp(alg, "ed25519") == 0) {
            bench_ed25519_verify(runs, msg_len, csv);
        } else {
            fprintf(stderr, "Unknown verify alg: %s\n", alg);
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    /* --------------- ENC MODE (AEAD ENCRYPT) --------------- */
    if (strcmp(mode, "enc") == 0) {
        if (argc < 6) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        const char *alg    = argv[2];
        size_t msg_len     = (size_t)strtoul(argv[3], NULL, 10);
        int runs           = atoi(argv[4]);
        const char *csv    = argv[5];

        if (strcmp(alg, "aes256gcm") == 0) {
            bench_aes256gcm_encrypt(runs, msg_len, csv);
        } else if (strcmp(alg, "chacha20poly1305") == 0) {
            bench_chacha20poly1305_encrypt(runs, msg_len, csv);
        } else if (strcmp(alg, "ascon128") == 0) {
            bench_ascon128_encrypt(runs, msg_len, csv);
        } else {
            fprintf(stderr, "Unknown enc alg: %s\n", alg);
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    /* --------------- DEC MODE (AEAD DECRYPT) --------------- */
    if (strcmp(mode, "dec") == 0) {
        if (argc < 6) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        const char *alg    = argv[2];
        size_t msg_len     = (size_t)strtoul(argv[3], NULL, 10);
        int runs           = atoi(argv[4]);
        const char *csv    = argv[5];

        if (strcmp(alg, "aes256gcm") == 0) {
            bench_aes256gcm_decrypt(runs, msg_len, csv);
        } else if (strcmp(alg, "chacha20poly1305") == 0) {
            bench_chacha20poly1305_decrypt(runs, msg_len, csv);
        } else if (strcmp(alg, "ascon128") == 0) {
            bench_ascon128_decrypt(runs, msg_len, csv);
        } else {
            fprintf(stderr, "Unknown dec alg: %s\n", alg);
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    /* --------------- KEM KEYGEN MODE --------------- */
    if (strcmp(mode, "kemkeygen") == 0) {
        if (argc < 5) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        const char *alg = argv[2];
        int runs        = atoi(argv[3]);
        const char *csv = argv[4];

        if      (strcmp(alg, "mlkem512")        == 0) bench_kem_keygen("ML-KEM-512",runs, csv);
        else if (strcmp(alg, "mlkem768")        == 0) bench_kem_keygen("ML-KEM-768",runs, csv);
        else if (strcmp(alg, "mlkem1024")       == 0) bench_kem_keygen("ML-KEM-1024",runs, csv);
        else if (strcmp(alg, "hqc128")          == 0) bench_kem_keygen("HQC-128",runs, csv);
        else if (strcmp(alg, "hqc192")          == 0) bench_kem_keygen("HQC-192",runs, csv);
        else if (strcmp(alg, "hqc256")          == 0) bench_kem_keygen("HQC-256",runs, csv);
        else if (strcmp(alg, "bike_l1")         == 0) bench_kem_keygen("BIKE-L1",runs, csv);
        else if (strcmp(alg, "bike_l3")         == 0) bench_kem_keygen("BIKE-L3",runs, csv);
        else if (strcmp(alg, "cm348864")        == 0) bench_kem_keygen("Classic-McEliece-348864",runs, csv);
        else if (strcmp(alg, "cm6688128")       == 0) bench_kem_keygen("Classic-McEliece-6688128",runs, csv);
        else if (strcmp(alg, "ntru_hps2048509") == 0) bench_kem_keygen("NTRU-HPS-2048-509",runs, csv);
        else if (strcmp(alg, "ntru_hps4096821") == 0) bench_kem_keygen("NTRU-HPS-4096-821",runs, csv);
        else if (strcmp(alg, "ntru_hrss701")    == 0) bench_kem_keygen("NTRU-HRSS-701",runs, csv);
        else if (strcmp(alg, "sntrup761")       == 0) bench_kem_keygen("sntrup761",runs, csv);
        else if (strcmp(alg, "frodokem640aes")  == 0) bench_kem_keygen("FrodoKEM-640-AES",runs, csv);
        else if (strcmp(alg, "frodokem976aes")  == 0) bench_kem_keygen("FrodoKEM-976-AES",runs, csv);
        else if (strcmp(alg, "x25519")          == 0) bench_x25519_ecdh(runs, csv);
        else {
            fprintf(stderr, "Unknown KEM keygen alg: %s\n", alg);
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    /* --------------- KEM ENCAPS MODE --------------- */
    if (strcmp(mode, "kemencaps") == 0) {
        if (argc < 5) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        const char *alg = argv[2];
        int runs        = atoi(argv[3]);
        const char *csv = argv[4];

        if      (strcmp(alg, "mlkem512")        == 0) bench_kem_encaps("ML-KEM-512", runs, csv);
        else if (strcmp(alg, "mlkem768")        == 0) bench_kem_encaps("ML-KEM-768", runs, csv);
        else if (strcmp(alg, "mlkem1024")       == 0) bench_kem_encaps("ML-KEM-1024", runs, csv);
        else if (strcmp(alg, "hqc128")          == 0) bench_kem_encaps("HQC-128", runs, csv);
        else if (strcmp(alg, "hqc192")          == 0) bench_kem_encaps("HQC-192", runs, csv);
        else if (strcmp(alg, "hqc256")          == 0) bench_kem_encaps("HQC-256", runs, csv);
        else if (strcmp(alg, "bike_l1")         == 0) bench_kem_encaps("BIKE-L1", runs, csv);
        else if (strcmp(alg, "bike_l3")         == 0) bench_kem_encaps("BIKE-L3", runs, csv);
        else if (strcmp(alg, "cm348864")        == 0) bench_kem_encaps("Classic-McEliece-348864", runs, csv);
        else if (strcmp(alg, "cm6688128")       == 0) bench_kem_encaps("Classic-McEliece-6688128", runs, csv);
        else if (strcmp(alg, "ntru_hps2048509") == 0) bench_kem_encaps("NTRU-HPS-2048-509", runs, csv);
        else if (strcmp(alg, "ntru_hps4096821") == 0) bench_kem_encaps("NTRU-HPS-4096-821", runs, csv);
        else if (strcmp(alg, "ntru_hrss701")    == 0) bench_kem_encaps("NTRU-HRSS-701", runs, csv);
        else if (strcmp(alg, "sntrup761")       == 0) bench_kem_encaps("sntrup761", runs, csv);
        else if (strcmp(alg, "frodokem640aes")  == 0) bench_kem_encaps("FrodoKEM-640-AES", runs, csv);
        else if (strcmp(alg, "frodokem976aes")  == 0) bench_kem_encaps("FrodoKEM-976-AES", runs, csv);
        else {
            fprintf(stderr, "Unknown KEM encaps alg: %s\n", alg);
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }


    /* --------------- KEM DECAPS MODE --------------- */
    if (strcmp(mode, "kemdecaps") == 0) {
        if (argc < 5) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        const char *alg = argv[2];
        int runs        = atoi(argv[3]);
        const char *csv = argv[4];

        if      (strcmp(alg, "mlkem512")        == 0) bench_kem_decaps("ML-KEM-512", runs, csv);
        else if (strcmp(alg, "mlkem768")        == 0) bench_kem_decaps("ML-KEM-768", runs, csv);
        else if (strcmp(alg, "mlkem1024")       == 0) bench_kem_decaps("ML-KEM-1024", runs, csv);
        else if (strcmp(alg, "hqc128")          == 0) bench_kem_decaps("HQC-128", runs, csv);
        else if (strcmp(alg, "hqc192")          == 0) bench_kem_decaps("HQC-192", runs, csv);
        else if (strcmp(alg, "hqc256")          == 0) bench_kem_decaps("HQC-256", runs, csv);
        else if (strcmp(alg, "bike_l1")         == 0) bench_kem_decaps("BIKE-L1", runs, csv);
        else if (strcmp(alg, "bike_l3")         == 0) bench_kem_decaps("BIKE-L3", runs, csv);
        else if (strcmp(alg, "cm348864")        == 0) bench_kem_decaps("Classic-McEliece-348864", runs, csv);
        else if (strcmp(alg, "cm6688128")       == 0) bench_kem_decaps("Classic-McEliece-6688128", runs, csv);
        else if (strcmp(alg, "ntru_hps2048509") == 0) bench_kem_decaps("NTRU-HPS-2048-509", runs, csv);
        else if (strcmp(alg, "ntru_hps4096821") == 0) bench_kem_decaps("NTRU-HPS-4096-821", runs, csv);
        else if (strcmp(alg, "ntru_hrss701")    == 0) bench_kem_decaps("NTRU-HRSS-701", runs, csv);
        else if (strcmp(alg, "sntrup761")       == 0) bench_kem_decaps("sntrup761", runs, csv);
        else if (strcmp(alg, "frodokem640aes")  == 0) bench_kem_decaps("FrodoKEM-640-AES", runs, csv);
        else if (strcmp(alg, "frodokem976aes")  == 0) bench_kem_decaps("FrodoKEM-976-AES", runs, csv);
        else {
            fprintf(stderr, "Unknown KEM decaps alg: %s\n", alg);
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    /* --------------- KDF MODE --------------- */
    if (strcmp(mode, "kdf") == 0) {
        if (argc < 6) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        const char *alg       = argv[2];
        size_t secret_len     = (size_t)strtoul(argv[3], NULL, 10);
        int runs              = atoi(argv[4]);
        const char *csv       = argv[5];

        if (strcmp(alg, "hkdf_sha256") == 0) {
            bench_hkdf_sha256(secret_len, runs, csv);
        } else if (strcmp(alg, "hkdf_sha384") == 0) {
            bench_hkdf_sha384(secret_len, runs, csv);
        } else if (strcmp(alg, "hkdf_sha512") == 0) {
            bench_hkdf_sha512(secret_len, runs, csv);
        } else if (strcmp(alg, "hmac_sha256") == 0) {
            bench_hmac_sha256(secret_len, runs, csv);
        } else if (strcmp(alg, "cmac_aes256") == 0) {
            bench_cmac_aes256(secret_len, runs, csv);
        } else if (strcmp(alg, "blake2b") == 0) {
            bench_blake2b_kdf(secret_len, runs, csv);
        } else if (strcmp(alg, "shake128") == 0) {
            bench_shake128_kdf(secret_len, runs, csv);
        } else if (strcmp(alg, "shake256") == 0) {
            bench_shake256_kdf(secret_len, runs, csv);
        } else {
            fprintf(stderr, "Unknown KDF alg: %s\n", alg);
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    usage(argv[0]);
    return EXIT_FAILURE;
}
