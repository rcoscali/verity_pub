/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//gcc -I../../core/include -I../../../external/boringssl/include verity_pub.c -o verity_pub /usr/local/src2/android-7.1.1_r11/out/host/linux-x86/obj/STATIC_LIBRARIES/libcrypto_static_intermediates/libcrypto_static.a -lpthread
// For test:
// ./verity_pub -from verity_key verity.pub.der
// ./verity_pub -to verity.pub.der verity_key.2
// ./verity_pub -from verity_key.2 verity.pub.der.2
// cmp verity_key verity_key.2
//  => no output
// cmp verity.pub.der verity.pub.der.2
//  => no output
// If DO_LOG defined all printed fields must be equals

#define DO_LOG 1
#if DO_LOG
#define flog(stream, msg...)	fprintf(stream, msg)
#else
#define flog(stream, msg...)	do { } while (0)
#endif

#define _GNU_SOURCE  /* needed for asprintf */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* HACK: we need the RSAPublicKey struct
 * but RSA_verify conflits with openssl */
#define RSA_verify RSA_verify_mincrypt
#include "mincrypt/rsa.h"
#undef RSA_verify

#include <openssl/bio.h>
#include <openssl/bytestring.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/mem.h>

static BIO *g_bio_error = NULL;

// Convert OpenSSL RSA private key to android pre-computed RSAPublicKey format.
// Lifted from secure adb's mincrypt key generation.
int
convert_to_mincrypt_format(RSA *rsa, RSAPublicKey *pkey)
{
  int ret = -1;
  unsigned int i;

  do
    {
      if (!pkey) break;
      if (RSA_size(rsa) != RSANUMBYTES) break;

      BN_CTX* ctx = BN_CTX_new();
      BIGNUM* r32 = BN_new();
      BIGNUM* rr = BN_new();
      BIGNUM* r = BN_new();
      BIGNUM* rem = BN_new();
      BIGNUM* n = BN_new();
      BIGNUM* n0inv = BN_new();
      
      BN_set_bit(r32, 32);
      BN_copy(n, rsa->n);
      BN_set_bit(r, RSANUMWORDS * 32);
      BN_mod_sqr(rr, r, n, ctx);
      BN_div(NULL, rem, n, r32, ctx);
      BN_mod_inverse(n0inv, rem, r32, ctx);
      
      pkey->len = RSANUMWORDS;
      pkey->n0inv = 0 - BN_get_word(n0inv);
      for (i = 0; i < RSANUMWORDS; i++) {
        BN_div(rr, rem, rr, r32, ctx);
        pkey->rr[i] = BN_get_word(rem);
        BN_div(n, rem, n, r32, ctx);
        pkey->n[i] = BN_get_word(rem);
      }
      pkey->exponent = BN_get_word(rsa->e);
      
      ret = 0;
      
      flog(stderr,
	   "public key length = %lu bits (%lu bytes)\n",
	   pkey->len * sizeof(uint32_t) * 8,
	   pkey->len * sizeof(uint32_t));
      flog(stderr,
	   "public key exponent = %d\n",
	   pkey->exponent);
      flog(stderr,
	   "public key modulus = \n");
#if DO_LOG      
      for (int ix = 0; ix < RSANUMWORDS; ix++)
	{
	  flog(stderr,
	       "%02x%02x%02x%02x",
	       pkey->n[RSANUMWORDS -1-ix] >> 24,
	       (pkey->n[RSANUMWORDS -1-ix] >> 16) & 0xff,
	       (pkey->n[RSANUMWORDS -1-ix] >> 8) & 0xff,
	       pkey->n[RSANUMWORDS -1-ix] & 0xff);
	}
#endif
      flog(stderr, "\n");
      
      BN_free(n0inv);
      BN_free(n);
      BN_free(rem);
      BN_free(r);
      BN_free(rr);
      BN_free(r32);
      BN_CTX_free(ctx);
    }
  while (0);
  
  return ret;
}

// Convert android pre-computed RSAPublicKey public key format to OpenSSL RSA public key.
// Lifted from secure adb's mincrypt key generation.
// If success free derbytes with OPENSSL_free
int
convert_from_mincrypt_format(RSAPublicKey *pkey, uint8_t **derbytes, size_t *bytes)
{
  int ret = -1;

  do
    {
      if (!pkey) break;
      if (derbytes && !bytes) break;
      if (pkey->len != RSANUMWORDS) break;

      flog(stderr,
	   "public key length = %lu bits (%lu bytes)\n",
	   pkey->len * sizeof(uint32_t) * 8,
	   pkey->len * sizeof(uint32_t));
      flog(stderr,
	   "public key exponent = %d\n",
	   pkey->exponent);
      
      BN_CTX* ctx = BN_CTX_new();
      uint8_t n[RSANUMBYTES];
      int ix = 0, _bytes;
      RSA *rsa = RSA_new();
      
      rsa->e = BN_new();
      rsa->n = BN_new();

      BN_set_word(rsa->e, (BN_ULONG)pkey->exponent);
      flog(stderr,
	   "public key modulus = \n");
      for (ix = 0; ix < RSANUMWORDS; ix++)
	{
	  n[ix*4] = pkey->n[RSANUMWORDS -1-ix] >> 24;
	  n[ix*4+1] = (pkey->n[RSANUMWORDS -1-ix] >> 16) & 0xff;
	  n[ix*4+2] = (pkey->n[RSANUMWORDS -1-ix] >> 8) & 0xff;
	  n[ix*4+3] = pkey->n[RSANUMWORDS -1-ix] & 0xff;
	  flog(stderr,
	       "%02x%02x%02x%02x",
	       n[ix*4], n[ix*4+1],
	       n[ix*4+2], n[ix*4+3]);
	}
      flog(stderr, "\n");
      BN_bin2bn((const uint8_t *)n, RSANUMBYTES, rsa->n);
      if (!RSA_check_key(rsa))
	{
	  fprintf(stderr, "Bad RSA key\n");
	  break;
	}

      if (derbytes)
	RSA_public_key_to_bytes(derbytes, (size_t *)bytes, rsa);
      else if (bytes)
	*bytes = i2d_RSAPublicKey(rsa, NULL);

    }
  while (0);
  
  return ret;
}

void
usage()
{
  fprintf(stderr,
	  "Usage: verity_pub --to <path-to-openssl-key> <path-to-mincrypt-key> |"
	  " --from <path-to-mincrypt-key> <path-to-openssl-key>\n");
  fprintf(stderr,
	  "Convert an RSA pub key der stream to/from a mincrypt RSA key used\n"
	  "for verity on android.\n"
	  "More specificaly the target format of --to option allows to create\n"
	  "the file /verity_pub that is found at root of boot.img\n");
}

int
main(int argc, char **argv)
{
  BIO *infile = (BIO *)NULL;
  RSAPublicKey pkey;
  uint8_t *derstream = (uint8_t *)NULL;
  size_t derbytes = 0;
  int ret = -1;
  
  /* BIO descriptor for logging OpenSSL errors to stderr */
  if ((g_bio_error = BIO_new_fd(STDERR_FILENO, BIO_NOCLOSE)) == NULL)
    {
      printf("Failed to allocate a BIO handle for error output\n");
      return 1;
    }

  ERR_load_crypto_strings();
  
  if (argc == 4 && !(strncmp(argv[1], "--from", 6) && strncmp(argv[1], "-from", 5)))
    {
      infile = BIO_new_file(argv[2], "r");
      if (!infile)
	ERR_print_errors(g_bio_error);

      else
	{
	  BIO *outfile = NULL;
	  
	  BIO_read(infile, &pkey, sizeof(pkey));
	  
	  if (convert_from_mincrypt_format(&pkey, &derstream, &derbytes))
	    {
	      do
		{
		  outfile = BIO_new_file(argv[3], "w");
		  if (!outfile)
		    {
		      perror("Opening file for writing");
		      break;
		    }
		  
		  BIO_write(outfile, derstream, derbytes);
		  BIO_flush(outfile);

		  fprintf(stderr, "RSA key written to %s\n", argv[3]);
		  
		  ret = 0;
		}
	      while (0);
	    }

	  if (outfile)
	    BIO_free_all(outfile);	      
	}
    }
  else if (argc == 4 && !(strncmp(argv[1], "--to", 4) && strncmp(argv[1], "-to", 3)))
    {
      CBS cbs;
      RSA *rsa = (RSA *)NULL;

      infile = BIO_new_file(argv[2], "r");
      if (!infile)
	ERR_print_errors(g_bio_error);

      else
	{
	  do
	    {
	      BIO *outfile = (BIO *)NULL;
	      
	      if (!BIO_read_asn1(infile,
				 (uint8_t **)&derstream, &derbytes,
				 1024*1024))
		{
		  ERR_print_errors(g_bio_error);
		  break;
		}

	      CBS_init(&cbs, derstream, derbytes);
	      rsa = RSA_parse_public_key(&cbs);
	      if (! rsa)
		{
		  ERR_print_errors(g_bio_error);
		  break;
		}
	      
	      if (convert_to_mincrypt_format(rsa, &pkey))
		{
		  fprintf(stderr,
			  "error: convertion to mincrypt format failed !\n");
		  break;
		}
	      
	      outfile = BIO_new_file(argv[3], "wb");
	      if (!outfile)
		{
		  ERR_print_errors(g_bio_error);
		  break;
		}
	      int wrsz = BIO_write(outfile, (const void *)&pkey, sizeof(pkey));
	      if (wrsz < 0)		
		{
		  ERR_print_errors(g_bio_error);
		  break;
		}
	      if (wrsz != sizeof(pkey))
		{
		  fprintf(stderr,
			  "error: short write in %s: expected %lu but wrote %d\n",
			  argv[3], sizeof(pkey), wrsz);
		  break;
		}
	      BIO_flush(outfile);

	      fprintf(stderr, "Verity key written to %s\n", argv[3]);
	      ret = 0;

	      if (outfile)
		BIO_free_all(outfile);
	    }
	  while (0);
	}
    }
  else
    usage();
  
  if (derstream)
    OPENSSL_free(derstream);
  
  if (infile)
    BIO_free_all(infile);
  
  exit (ret);
}
