# verity_pub
Verity key (pub RSA) convert utility

In order to build, at now, you need to be in an android tree, in system/extras/verity for ex.
I'll change that later ...

A binary for ubuntu 16.04 is available.

The Verity_key in here is the one extracted from the angler boot.img.

No full tests were still conducted, then consider as alpha version.
The test in Makefile consist in:

    	# Create RSA pub key Openssl der stream from verity_key
	./verity_pub --from verity_key verity_step1.pub.der
	# Then create the RSAPublicKey struct from the der stream
	./verity_pub --to verity_step1.pub.der verity_key_step2
	# Then once again
	./verity_pub --from verity_key_step2 verity_step3.pub.der

        # Compare both start & final: all must be the sames (no ouput)
	cmp verity_key verity_key_step2
	cmp verity_step1.pub.der verity_step3.pub.der

