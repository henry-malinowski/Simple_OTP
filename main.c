/**
 * input file is set to: "input.txt" for testing
 * output file is set to "output.txt" for testing
 * one-time-pad is is set to "testing.otp" for testing
 */

#include <stdio.h>
#include <immintrin.h>  // Intel random generation engine
#include <stdnoreturn.h>

#define ULL_SIZE sizeof(unsigned long long)

//#define REAL_TIME_DECRYPT 1
#define DECRYPT 1

#ifndef DECRYPT
#define ENCRYPT 1
#endif

typedef union {
    unsigned long long ull;
    unsigned char c[ULL_SIZE];
} char_container;

long fsize(FILE *fp);

/**
 * Encrypts in input file, using random numbers generated from a secure source
 * and outputs the random bits and encrypted message.
 * @param plain_text [in]  An open connection to the plain-text file in binary read mode.
 * @param output     [out] An open connection to the output file in binary write mode.
 * @param otp        [out] An open connection to a file that will contain the one-time-pad for \p output.
 */
void encrypt(FILE* plain_text, FILE* ouput, FILE* otp);


/**
 * Decrypts in input file using a one-time-pad and directing the output to a specified output.
 * @param cipher_text [in]  An open connection to the cipher-text file in binary read mode.
 * @param output      [out] An open connection to the output file in binary write mode.
 * @param otp         [in]  An open connection to the one-time-pad in binary read mode.
 */
void decrypt(FILE* cipher_text, FILE* output, FILE* otp);


noreturn void invalid_file_size(const char *str);
noreturn void size_missmatch(void);
noreturn void print_usage(int argc, char* const argv[argc]);

/**
 * The core logic for the program.
 * Program arguments:
 * * --help Displays the help message.
 * * -e Encrypts an input file and outputs the one-time-pad with a unique file name
 * * -d Decrypts an input file and it's one-time-pad
 *
 * @param argc The number of arguments present in \p argc.
 * @param argv The input arguments in the form of NULL-terminated strings.
 * @return A status code to the caller (likely the OS).
 * @retval 0 Indicates the program exited successfully.
 * @retval 1 Indicates the program failed in some generic fashion.
 * @retval 2 Indicates the input file size is to large.
 * @retval 3 Indicates that the Intel random number engine failed to return properly.
 */
int main(int argc, char* argv[argc]) {
    FILE *input_file, *output_file, *opt_file;

#ifdef ENCRYPT
        input_file = fopen("input.txt", "rb");
        opt_file = fopen("testing.otp", "wb");
        output_file = fopen("output.txt", "wb");

        encrypt(input_file, output_file, opt_file);
#else
        input_file = fopen("output.txt", "rb");
        opt_file = fopen("testing.otp", "rb");
        output_file = fopen("output_test.txt", "wb");

        decrypt(input_file, output_file, opt_file);
#endif

    // close file connections
    fclose(input_file);
    fclose(opt_file);
    fclose(output_file);
}


void encrypt(FILE* plain_text, FILE* ouput, FILE* otp) {
    // Error check the input files
    long cipher_size = fsize(plain_text);
    if (cipher_size <= 0) {
        invalid_file_size("plaintext");
    }

    ldiv_t blocks_r = ldiv(cipher_size, ULL_SIZE);

    char_container one_time_pad;
    char_container input_pad = {.ull = 0ULL};

    /* main encryption loop
     *
     */
    for (long i = 0; i < blocks_r.quot; ++i) {
        // generate 64-bits (8 bytes) of random bits
        if(!_rdrand64_step(&one_time_pad.ull)) {
            fprintf(stderr, "failed to read from sysrand\n");
            exit(3);
        }

        // write the bits out to the one-time-pad
        fwrite(one_time_pad.c, sizeof(char), ULL_SIZE, otp);

        // read in the next 8 bytes in
        fread(input_pad.c, sizeof(char), ULL_SIZE, plain_text);

        // XOR the pads against each other
        input_pad.ull ^= one_time_pad.ull;

        // write the XORed plain_text to the output file
        fwrite(input_pad.c, sizeof(char), ULL_SIZE, ouput);
    }

    // handle remaining bytes using the same logic as above
    if (blocks_r.rem) {
        size_t remainder = (size_t) blocks_r.rem;
        printf("debug: handling a remainder of %zu bytes\n", remainder);

        if(!_rdrand64_step(&one_time_pad.ull)) {
            fprintf(stderr, "failed to read from sysrand\n");
            exit(3);
        }
        fwrite(one_time_pad.c, sizeof(char), remainder, otp);
        fread(input_pad.c, sizeof(char), remainder, plain_text);
        input_pad.ull ^= one_time_pad.ull;
        fwrite(input_pad.c, sizeof(char), remainder, ouput);
    }
}


void decrypt(FILE* cipher_text, FILE* output, FILE* otp) {
    // Error check the input files
    long cipher_size = fsize(cipher_text);
    if (cipher_size <= 0) {
        invalid_file_size("cipher text");
    }

    long otp_size = fsize(otp);
    if (otp_size <= 0) {
        invalid_file_size("one-time-pad");
    }

    if (cipher_size != otp_size) {
        size_missmatch();
    }

    ldiv_t blocks_r = ldiv(cipher_size, ULL_SIZE);
    char_container one_time_pad = {0}, output_pad = {0};

    /* Core decryption loop
     * - Reads in ULL_SIZE bytes from the one-time-pad
     * - Reads in ULL_SIZE bytes from the cipher_text
     * - XORs the bytes against each-other and stores them back into output_pad
     * - Writes the bytes out one byte at a time
     */
    for (size_t i = 0; i < blocks_r.quot; ++i) {
        fread(one_time_pad.c, sizeof(char), ULL_SIZE, otp);
        fread(output_pad.c, sizeof(char), ULL_SIZE, cipher_text);

        output_pad.ull ^= one_time_pad.ull;
        fwrite(output_pad.c, sizeof(char), ULL_SIZE, output);
    }

    // handle remaining text using the same logic as above
    if (blocks_r.rem) {
        size_t remain = (size_t) blocks_r.rem;
        fread(one_time_pad.c, sizeof(char), remain, otp);
        fread(output_pad.c, sizeof(char), remain, cipher_text);

        output_pad.ull ^= one_time_pad.ull;
        fwrite(output_pad.c, sizeof(char), ULL_SIZE, output);
    }
}


long fsize(FILE *fp) {
    long prev = ftell(fp);
    fseek(fp, 0L, SEEK_END);

    long sz = ftell(fp);
    fseek(fp, prev, SEEK_SET); //go back to where we were

    return sz;
}


noreturn void invalid_file_size(const char *str) {
    fprintf(stderr, "fatal: invalid file size \"%s\"(greater than 2GiB or empty file)\n", str);
    exit(2);
}


noreturn void size_missmatch(void) {
    fprintf(stderr, "fatal: size mismatch during decryption\n");
    fprintf(stderr, "       cipher text length does not equal the length of the one-time-pad\n");
    exit(3);
}
