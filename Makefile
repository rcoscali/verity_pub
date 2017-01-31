
PROGRAM:= verity_pub

SRCS := verity_pub.c


.PHONY: all tests test_step1 test_step2 test_step3

all: $(PROGRAM) tests

verity_pub: verity_pub.c
	gcc -I../../core/include -I../../../external/boringssl/include verity_pub.c -o verity_pub /usr/local/src2/android-7.1.1_r11/out/host/linux-x86/obj/STATIC_LIBRARIES/libcrypto_static_intermediates/libcrypto_static.a -lpthread

tests: test_step1 test_step2 test_step3
	cmp verity_key verity_key_step2
	cmp verity_step1.pub.der verity_step3.pub.der

test_step1:
	./verity_pub --from verity_key verity_step1.pub.der

test_step2:
	./verity_pub --to verity_step1.pub.der verity_key_step2

test_step3:
	./verity_pub --from verity_key_step2 verity_step3.pub.der

