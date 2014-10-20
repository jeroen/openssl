# There openssl libraries were compiled with the Rtools gcc tool chain.
setInternet2()
download.file("http://www.stat.ucla.edu/~jeroen/files/openssl-1.0.1j.zip", "lib.zip", quiet = TRUE)
dir.create("../windows", showWarnings = FALSE)
unzip("lib.zip", exdir = "../windows")
