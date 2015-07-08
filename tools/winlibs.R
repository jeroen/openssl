# Build against openssl libraries that were compiled with the Rtools gcc toolchain.
if(!file.exists("../windows/openssl-1.0.1j/include/openssl/ssl.h")){
  setInternet2()
  download.file("https://github.com/rwinlib/openssl/archive/v1.0.1j.zip", "lib.zip", quiet = TRUE)
  dir.create("../windows", showWarnings = FALSE)
  unzip("lib.zip", exdir = "../windows")
  unlink("lib.zip")
}
