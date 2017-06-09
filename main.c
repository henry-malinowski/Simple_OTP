/**
 * input file is set to: "input.txt" for testing
 * output file is set to "output.txt" for testing
 * one-time-pad is is set to "testing.otp" for testing
 *
 * SIGSEGV if files aren't provided
 */

#include <stdio.h>
#include <immintrin.h>  // Intel random generation engine
#include <stdnoreturn.h>
#include <stdbool.h>

#define ULL_SIZE sizeof(unsigned long long)

//#define REAL_TIME_DECRYPT 1
//#define DECRYPT 1

#ifndef DECRYPT
#define ENCRYPT 1
#endif

typedef union {
    unsigned char c[ULL_SIZE];
    unsigned long long ull;
} char_container;

long
fsize(FILE *fp);

/**
 * Encrypts in input file, using random numbers generated from a secure source
 * and outputs the random bits and encrypted message.
 * @param plain_text [in]  An open connection to the plain-text file in binary read mode.
 * @param output     [out] An open connection to the output file in binary write mode.
 * @param otp        [out] An open connection to a file that will contain the one-time-pad for \p output.
 */
void
encrypt(FILE* plain_text, FILE* ouput, FILE* otp);


/**
 * Decrypts in input file using a one-time-pad and directing the output to a specified output.
 * @param cipher_text [in]  An open connection to the cipher-text file in binary read mode.
 * @param output      [out] An open connection to the output file in binary write mode.
 * @param otp         [in]  An open connection to the one-time-pad in binary read mode.
 */
void
decrypt(FILE* cipher_text, FILE* output, FILE* otp);


noreturn void
invalid_file_size(const char *str);


noreturn void
size_missmatch(void);


noreturn void
print_usage(int argc, char* const argv[argc])
{
    fprintf(stderr, "debug: print usage has not been implemented yet\n");
    exit(2);
}

typedef enum {OTP_ENCRYPT, OTP_DECRYPT, OTP_NULLMODE, OTP_ERROR} E_PROGRAM_MODE ;

/**
 * The core logic for the program.
 * Program arguments:
 * * --help / -? Displays the help message.
 * * -e / --encrypt Encrypts an input file and outputs the one-time-pad with a unique file name
 * * -d / --decrypt Decrypts an input file and it's one-time-pad
 * * -p / --one-time-pad Selects a name for the one-time-pad
 * * -o output file path/name (optional)
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
    FILE *input_file, *output_file, *otp_file;
    char const *input_file_name = NULL;
    char const *outpad_file = NULL;
    char const *otp_file_name = NULL;
    E_PROGRAM_MODE program_mode = OTP_NULLMODE;

    bool verbose_print = false;
    FILE *verbose_printer = fopen("/dev/null", "w+");

    if (argc <= 1) {
        fprintf(stderr, "Program requires arguments\n");
        print_usage(argc, argv);
    }

    // Process command line arguments
    for (; (argc > 1) && (argv[1][0]) == '-'; --argc, ++argv) {
        switch (argv[1][1]) {
            case 'e':   // Encryption mode
                if (program_mode == OTP_DECRYPT) {
                    fprintf(stderr, "-e can not be used with -d\n");
                    exit(EXIT_FAILURE);
                }

                ++argv;
                --argc;
                input_file_name = argv[1];
                program_mode = OTP_ENCRYPT;
                break;
            case 'd':   // Decryption mode
                if (program_mode == OTP_ENCRYPT) {
                    fprintf(stderr, "-d can not be used -e\n");
                    exit(EXIT_FAILURE);
                }
                ++argv;
                --argc;
                input_file_name = argv[1];
                program_mode = OTP_DECRYPT;
                break;
            case 'p':   // Specify one time pad for decryption
                ++argv;
                --argc;
                otp_file_name = argv[1];
                break;
            case 'o':   // specify output file names or names (mode dependant)
                break;
            case 'v':   // enable verbose printing
                verbose_print = true;
                fclose(verbose_printer);
                verbose_printer = stdout;
                break;
            default:
                fprintf(stderr, "Invalid argument \"%s\"\n", argv[1]);
                print_usage(argc, argv);
        }
    }

    switch (program_mode) {
        case OTP_ENCRYPT:
            // open requested input file
            input_file = fopen(input_file_name, "rb");
            if (input_file == NULL) {
                fprintf(stderr, "%s is an invalid file name\n",
                        input_file_name);
                exit(EXIT_FAILURE);
            } else {
                fprintf(verbose_printer,
                        "debug: opened plain-text file - \"%s\" in read-binary\n",
                        input_file_name);
            }

            // open one-time-pad for writing
            if (otp_file_name == NULL) {
                fprintf(verbose_printer,
                        "debug: -p not used, selecting default output name\n");
                otp_file_name = "one-time-pad.otp";
            }
            otp_file = fopen(otp_file_name, "wb");
            if (otp_file == NULL) {
                fprintf(stderr, "Unable to open \"%s\" in write-binary\n",
                        otp_file_name);
                fclose(input_file);
                exit(EXIT_FAILURE);
            } else {
                fprintf(verbose_printer,
                        "debug: opened file - \"%s\" in write-binary\n",
                        otp_file_name);
            }

            // open output-file for writing
            output_file = fopen("output.txt", "wb");
            if (output_file == NULL) {
                fprintf(stderr,
                        "Unable to open \"output.txt\" in write-binary\n");
                fclose(input_file);
                fclose(otp_file);
                exit(EXIT_FAILURE);
            } else {
                fprintf(verbose_printer,
                        "debug: opened file - \"output.txt\" in write-binary\n");
            }

            encrypt(input_file, output_file, otp_file);

            // close file connections
            fclose(input_file);
            fclose(otp_file);
            fclose(output_file);
            break;
        case OTP_DECRYPT:
            // open requested input file
            input_file = fopen(input_file_name, "rb");
            if (input_file == NULL) {
                fprintf(stderr, "%s is an invalid file name\n",
                        input_file_name);
                exit(EXIT_FAILURE);
            } else {
                fprintf(verbose_printer,
                        "debug: opened cipher-text file - \"%s\" in read-binary\n",
                        input_file_name);
            }

            // open one-time-pad for writing
            otp_file = fopen(otp_file_name, "rb");
            if (otp_file == NULL) {
                fprintf(stderr, "Unable to open \"%s\" in read-binary\n",
                        otp_file_name);
                fclose(input_file);
                exit(EXIT_FAILURE);
            } else {
                fprintf(verbose_printer,
                        "debug: opened file - \"%s\" in read-binary\n",
                        otp_file_name);
            }

            // open output-file for writing
            output_file = fopen("decrypt_output.txt", "wb");
            if (output_file == NULL) {
                fprintf(stderr,
                        "Unable to open \"decrypt_output.txt\" in write-binary\n");
                fclose(input_file);
                fclose(otp_file);
                exit(EXIT_FAILURE);
            } else {
                fprintf(verbose_printer,
                        "debug: opened file - \"decrypt_output.txt\" in write-binary\n");
            }

            decrypt(input_file, output_file, otp_file);
            fclose(input_file);
            fclose(otp_file);
            fclose(output_file);
        default:
            break;
    }

    if (!verbose_print)
        fclose(verbose_printer);
}


void encrypt(FILE* plain_text, FILE* ouput, FILE* otp) {
    // Error check the input files
    long cipher_size = fsize(plain_text);
    if (cipher_size <= 0) {
        invalid_file_size("plaintext");
    }

    ldiv_t blocks_r = ldiv(cipher_size, ULL_SIZE);

    char_container one_time_pad;
    char_container cipher_pad = {.ull = 0ULL};

    /* Core encryption loop
     * - Reads in ULL_SIZE bytes from Intel rdrand64
     * - Reads in ULL_SIZE bytes from the plain_text into cipher_pad
     * - XORs the bytes against each other and store them back into cipher_pad
     * - Writes the bytes out one byte at a time
     */
    for (long i = 0; i < blocks_r.quot; ++i)
    {
        // generate 64-bits (8 bytes) of random bits
        if(!_rdrand64_step(&one_time_pad.ull))
        {
            fprintf(stderr, "failed to read from sysrand\n");
            exit(3);
        }

        // write the bits out to the one-time-pad
        fwrite(one_time_pad.c, sizeof(char), ULL_SIZE, otp);

        // read in the next 8 bytes in
        fread(cipher_pad.c, sizeof(char), ULL_SIZE, plain_text);

        // XOR the pads against each other
        cipher_pad.ull ^= one_time_pad.ull;

        // write the new cipher_text to the output file
        fwrite(cipher_pad.c, sizeof(char), ULL_SIZE, ouput);
    }

    // handle remaining bytes using the same logic as above
    if (blocks_r.rem)
    {
        size_t remain = (size_t) blocks_r.rem;
        printf("debug: handling a remaining %zu bytes\n", remain);

        if(!_rdrand64_step(&one_time_pad.ull))
        {
            fprintf(stderr, "failed to read from sysrand\n");
            exit(3);
        }

        fwrite(one_time_pad.c, sizeof(char), remain, otp);
        fread(cipher_pad.c, sizeof(char), remain, plain_text);
        cipher_pad.ull ^= one_time_pad.ull;
        fwrite(cipher_pad.c, sizeof(char), remain, ouput);
    }
}


void decrypt(FILE* cipher_text, FILE* output, FILE* otp) {
    // Error check the input files
    long cipher_size = fsize(cipher_text);
    if (cipher_size <= 0)
        invalid_file_size("cipher text");

    long otp_size = fsize(otp);
    if (otp_size <= 0)
        invalid_file_size("one-time-pad");

    if (cipher_size != otp_size)
        size_missmatch();

    ldiv_t blocks_r = ldiv(cipher_size, ULL_SIZE);
    char_container one_time_pad = {0}, cipher_pad = {0};

    /* Core decryption loop
     * - Reads in ULL_SIZE bytes from the one-time-pad
     * - Reads in ULL_SIZE bytes from the cipher_text
     * - XORs the bytes against each-other and stores them back into cipher_pad
     * - Writes the bytes out one byte at a time
     */
    for (long i = 0; i < blocks_r.quot; ++i)
    {
        fread(one_time_pad.c, sizeof(char), ULL_SIZE, otp);
        fread(cipher_pad.c, sizeof(char), ULL_SIZE, cipher_text);

        cipher_pad.ull ^= one_time_pad.ull;
        fwrite(cipher_pad.c, sizeof(char), ULL_SIZE, output);
    }

    // handle remaining text using the same logic as above
    if (blocks_r.rem)
    {
        size_t remain = (size_t) blocks_r.rem;
        fread(one_time_pad.c, sizeof(char), remain, otp);
        fread(cipher_pad.c, sizeof(char), remain, cipher_text);

        cipher_pad.ull ^= one_time_pad.ull;
        fwrite(cipher_pad.c, sizeof(char), ULL_SIZE, output);
    }
}


long
fsize(FILE *fp)
{
    long prev = ftell(fp);
    fseek(fp, 0L, SEEK_END);

    long sz = ftell(fp);
    fseek(fp, prev, SEEK_SET); //go back to where we were

    return sz;
}


noreturn void invalid_file_size(const char *str)
{
    fprintf(stderr, "fatal: invalid file size \"%s\"(greater than 2GiB or empty file)\n", str);
    exit(2);
}


noreturn void size_missmatch(void)
{
    fprintf(stderr, "fatal: size mismatch during decryption\n");
    fprintf(stderr, "       cipher text length does not equal the length of the one-time-pad\n");
    exit(3);
}
