// This program is used to create test data for `test_bn`,
// so we can check we're able to correctly parse OpenSSL's BIGNUM binary format.
// A `bn_dumps.txt.gz` file is already shipped with the source code, so you
// don't need to run this program unless you want to generate a new test data
// file. See the `Makefile` for an easy way to do that (though you'll no doubt
// need to change the include and library paths).

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdio.h>

int dump_random_bn(unsigned int nbits) {
  unsigned char buf[256];
  BIGNUM *bn = BN_new();
  if (!bn) {
    fprintf(stderr, "BN_new failed\n");
    return 1;
  }

  if (!BN_rand(bn, nbits * 8, 0, 0)) {
    fprintf(stderr, "BN_rand failed\n");
    return 1;
  }

  int len = BN_bn2bin(bn, buf);

  printf("%05d ", nbits);
  for (int i = 0; i < len; i++) {
    printf("%02x", buf[i]);
  }
  printf(" ");
  char *dec = BN_bn2dec(bn);
  printf("%s\n", dec);
  OPENSSL_free(dec);
  BN_free(bn);
  return 0;
}

int main() {
  srand(42);
  for (int i = 0; i < 250; i++) {
    int nbits = 16 + rand() % (256 - 16);
    if (dump_random_bn(nbits))
      return 1;
  }
  return 0;
}
