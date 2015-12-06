// stripped down rawSHA1_fmt_plug.c

#include <stdio.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <string.h>
#include "arch.h"
#include "sha.h"
#include "common.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#define DIGEST_SIZE 20

#ifdef SIMD_COEF_32
#define NBKEYS                          (SIMD_COEF_32 * SIMD_PARA_SHA1)
#endif

#ifdef SIMD_COEF_32
#define PLAINTEXT_LENGTH                55
#define MIN_KEYS_PER_CRYPT              NBKEYS
#define MAX_KEYS_PER_CRYPT              NBKEYS
#endif

char itoa16[16] =
	"0123456789abcdef";
char itoa16u[16] =
	"0123456789ABCDEF";
char atoi16[0x100];

static int initialized = 0;

void common_init(void)
{
	char *pos;

	if (initialized) return;

	memset(atoi16, 0x7F, sizeof(atoi16));
	for (pos = itoa16; pos <= &itoa16[15]; pos++)
		atoi16[ARCH_INDEX(*pos)] = pos - itoa16;

	atoi16['A'] = atoi16['a'];
	atoi16['B'] = atoi16['b'];
	atoi16['C'] = atoi16['c'];
	atoi16['D'] = atoi16['d'];
	atoi16['E'] = atoi16['e'];
	atoi16['F'] = atoi16['f'];

	initialized = 1;
}

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}

void algorithm(unsigned char *input, unsigned int length, unsigned char Hash[])
{
	unsigned char fixed_key[16] = { 0x77, 0x21, 0x4d, 0x4b, 0x19, 0x6a, 0x87, 0xcd, 0x52, 0x00, 0x45, 0xfd, 0x20, 0xa5, 0x1d, 0x67};

	unsigned char intermediate_key[20] = {0};
	unsigned char intermediate_iv[20] = {0};
	SHA_CTX ctx;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, fixed_key, 16);
	SHA1_Update(&ctx, input, length);
	SHA1_Final(intermediate_key, &ctx);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, fixed_key, 16);
	SHA1_Update(&ctx, intermediate_key, 20);
	SHA1_Update(&ctx, input, length);
	SHA1_Final(intermediate_iv, &ctx);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, intermediate_key, 16);
	SHA1_Update(&ctx, intermediate_iv, 16);
	SHA1_Final(Hash, &ctx);
}

int main(int argc, char **argv)
{
	uint32_t input = 0; // "\x00\x00\x00\x00" to "\xFF\xFF\xFF\xFF" (UINT32_MAX ~ 4.3 billion!)
	unsigned long long i;
	common_init();

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <SHA1 file checksum>\n", argv[0]);
		exit(-1);
	}

	char *p = argv[1];
	unsigned char desired_hash[20];

	for (i = 0; i < 20; i++)
		desired_hash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	printf("Searching for ");
	print_hex(desired_hash, 20);

	unsigned char fixed_key[16] = { 0x77, 0x21, 0x4d, 0x4b, 0x19, 0x6a, 0x87, 0xcd, 0x52, 0x00, 0x45, 0xfd, 0x20, 0xa5, 0x1d, 0x67};
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char sse_buf[SHA_BUF_SIZ*sizeof(ARCH_WORD_32)*NBKEYS] = {0};
	JTR_ALIGN(MEM_ALIGN_SIMD) ARCH_WORD_32 intermediate_key[DIGEST_SIZE/4*NBKEYS] = {0};
	JTR_ALIGN(MEM_ALIGN_SIMD) ARCH_WORD_32 intermediate_iv[DIGEST_SIZE/4*NBKEYS] = {0};
	JTR_ALIGN(MEM_ALIGN_SIMD) ARCH_WORD_32 final_hash[DIGEST_SIZE/4*NBKEYS] = {0};

	fprintf(stderr, "MAX_KEYS_PER_CRYPT %d\n", MAX_KEYS_PER_CRYPT);
	fprintf(stderr, "CPU_NAME %s\n", CPU_NAME);
	fprintf(stderr, "MEM_ALIGN_SIMD %d\n", MEM_ALIGN_SIMD);
	fprintf(stderr, "SHA_BUF_SIZ %d\n", SHA_BUF_SIZ);
	fprintf(stderr, "SIMD_COEF_32 %d\n", SIMD_COEF_32);
	fprintf(stderr, "NBKEYS %d\n", NBKEYS);

	// for (i = 0; i < 1000000000; i += MAX_KEYS_PER_CRYPT) { // 1000M for benchmarking
	// for (i = 0; i < 16; i += MAX_KEYS_PER_CRYPT) { // 100M for testing
	for (i = 0; i < UINT32_MAX; i += MAX_KEYS_PER_CRYPT) {
		unsigned int j;
		int idx;
		int intermediate_key_idx;
		int intermediate_iv_idx;

		uint32_t input_loop;
		memset(sse_buf, 0, 64 * MAX_KEYS_PER_CRYPT); // clean input buffers

		/* intermediate_key = SHA1(fixed_key + input) */
		idx = 0;
		input_loop = input;
		for (j = 0; j < MAX_KEYS_PER_CRYPT; j++) {
			memcpy(sse_buf + idx, fixed_key, 16);
			memcpy(sse_buf + idx + 16, &input_loop, 4);
			// memcpy(sse_buf + idx + 16, "\x00\x00\x00\x00", 4); // for testing
			sse_buf[idx + 20] = 0x80;
			sse_buf[idx + 60] = 20<<3; // apend length, in SSEi_FLAT_IN mode BE swapping happens in SIMD code internally, so if you give it the bit count in BE format, the swapping would unswap it.
			idx += 64;
			input_loop++;
		}
		SIMDSHA1body(sse_buf, intermediate_key, NULL, SSEi_FLAT_IN|SSEi_OUTPUT_AS_INP_FMT|SSEi_FLAT_OUT);
		// print_hex((unsigned char*)sse_buf, 64);
		// print_hex((unsigned char*)intermediate_key, 20);

		/* intermediate_iv = SHA1(fixed_key + intermediate_key + input) */
		idx = 0;
		intermediate_key_idx = 0;
		input_loop = input;
		for (j = 0; j < MAX_KEYS_PER_CRYPT; j++) {
			// memcpy(sse_buf + idx, fixed_key, 16); // already in place
			memcpy(sse_buf + idx + 16, intermediate_key + intermediate_key_idx, 20);
			memcpy(sse_buf + idx + 16 + 20, &input_loop, 4);
			// memcpy(sse_buf + idx + 16 + 20, "\x00\x00\x00\x00", 4); // for testing
			sse_buf[idx + 40] = 0x80;
			sse_buf[idx + 60] = (char)(40<<3);
			sse_buf[idx + 61] = (40<<3) >> 8;
			idx += 64;
			intermediate_key_idx += 5;
			input_loop++;
		}
		SIMDSHA1body(sse_buf, intermediate_iv, NULL, SSEi_FLAT_IN|SSEi_OUTPUT_AS_INP_FMT|SSEi_FLAT_OUT);
		// print_hex((unsigned char*)sse_buf, 64);
		// print_hex((unsigned char*)intermediate_iv, 20);

		/* final_hash = SHA1(intermediate_key + intermediate_iv) */
		idx = 0;
		intermediate_key_idx = 0;
		intermediate_iv_idx = 0;
		memset(sse_buf, 0, 64 * MAX_KEYS_PER_CRYPT); // clean input buffers
		for (j = 0; j < MAX_KEYS_PER_CRYPT; j++) {
			memcpy(sse_buf + idx, intermediate_key + intermediate_key_idx, 16);
			memcpy(sse_buf + idx + 16, intermediate_iv + intermediate_iv_idx, 16);
			sse_buf[idx + 32] = 0x80;
			// sse_buf[idx + 60] = (char)(32<<3); // RHS is 0, hence commented out
			sse_buf[idx + 61] = (32<<3) >> 8;
			idx += 64;
			intermediate_key_idx += 5;
			intermediate_iv_idx += 5;
		}
		SIMDSHA1body(sse_buf, final_hash, NULL, SSEi_FLAT_IN|SSEi_OUTPUT_AS_INP_FMT|SSEi_FLAT_OUT);

		for (j = 0; j < MAX_KEYS_PER_CRYPT; j++) {
			if (!memcmp(desired_hash, final_hash + j * 5, 20)) {
				int num = input + j;
				int activation_bytes = ((num>>24)&0xff) | ((num<<8)&0xff0000) | ((num>>8)&0xff00) | ((num<<24)&0xff000000);
				printf("Found input to be %08x, activation_bytes => %08x\n", num, activation_bytes);
				exit(0);
			}
		}
		input = input_loop;
		// printf("%d\n", input);
	}

	// print_hex((unsigned char*)sse_buf, 64);
	// print_hex((unsigned char*)final_hash, 20);

	return 0;
}
