# Build against openssl libraries that were compiled with the Rtools gcc toolchain.
setInternet2()
download.file("http://jeroenooms.github.io/openssl/windows/openssl-1.0.1j.zip", "lib.zip", quiet = TRUE)
dir.create("../windows", showWarnings = FALSE)
unzip("lib.zip", exdir = "../windows")
