#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

void algorithm(unsigned char *input, unsigned int length, unsigned char Hash[])
{
	unsigned char fixed_key[16] = {0xFF}; // don't make data assumptions about this 16 byte key!

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

int main()
{
	uint32_t input = 0;
	unsigned char output[20];

	unsigned char desired_output[20] = {0}; // dummy value

	// UINT32_MAX ~ 4.3 billion!
	for(input = UINT32_MAX;; --input) { // explore 32-bit keyspace
		algorithm((unsigned char*)&input, 4, output);

		if (!memcmp(output, desired_output, 20)) {
			printf("Found input to be %08x\n", input);
			break;
		}

		if (input == 0) break;
	}

	return 0;
}
