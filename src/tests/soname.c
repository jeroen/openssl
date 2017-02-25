#include <openssl/opensslv.h>
#include <stdio.h>

int main () {
  printf(SHLIB_VERSION_NUMBER);
  return 0;
}
