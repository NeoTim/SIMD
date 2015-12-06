dummy:
	# gcc -ggdb -DJOHN_AVX -DHAVE_CRYPT -DHAVE_LIBDL -mavx2 -fsanitize=address -O2 main.c simd-intrinsics.c -lcrypto
	# gcc -O3 -DJOHN_AVX -DHAVE_CRYPT -DHAVE_LIBDL -mavx2 main.c simd-intrinsics.c -lcrypto
	gcc -Wall -Wextra -O3 -DJOHN_AVX2 -DHAVE_CRYPT -DHAVE_LIBDL -mavx2 main.c simd-intrinsics.c -lcrypto
run:
	./a.out eac2f95118012356d8bbe5a74fb35eb401e5451e
	# ./a.out ffffffffffffffffffffffffffffffffffffffff  # exhaust keyspace
	# 62689101
