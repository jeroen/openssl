### Builds OpenSSL static/shared libraries for R in msys
# Make sure that msys refers to the mingw included with rtools
#
## msys /etc/fstab looks like this:
# C:/RBuildTools/3.1/gcc-4.6.3 /mingw
#####

cd ~
curl -O https://www.openssl.org/source/openssl-1.0.1j.tar.gz
tar xzvf openssl-1.0.1j.tar.gz
cd openssl-1.0.1j
PATH=/c/Perl/bin:$PATH # assumes activestate perl

# Build for win32
mkdir -p ~/libssl/win32
PERL=/c/Perl/bin/perl ./configure mingw64 --prefix=~/libssl/win32 no-shared no-asm -m32
make 
make install

# Build for win64
mkdir -p ~/libssl/win64
PERL=/c/Perl/bin/perl ./configure mingw64 --prefix=~/libssl/win64 no-shared no-asm -m64
make 
make install

# Building 64bit executables might fail but static libraries should be OK.