# Building library archives

This program needs openssl(`libssl.a`, `libcrypto.a`) and wolfssl(`libwolfssl.a`) static library to build. You can download openssl and wolfssl repository from official websites, respectively.

## How to build openssl library archive

Run following commands inside openssl repo:

`./Configure no-shared enable-acvp-tests no-apps no-autoalginit no-autoerrinit no-tests no-dso`

After configuration, just simply build it:

`make`

Now there will be archive files named `libssl.a` and `libcrypto.a`. Simply copy those files to `ketu-firmware/tools/cavp_testing/libs`. Like this:

`cp *.a ketu-firmware/tools/cavp_testing/libs`

## How to build wolfssl library archive

Run following commands inside wolfssl repo:

`./configure --disable-shared --enable-static=yes --enable-cryptonly=yes --enable-aesgcm=yes --disable-aesgcm-stream CFLAGS=-DWOLFSSL_AEAD_ONLY`

After configuration, just simply build it:

`make`

Or if you want to build static library only(without other bothering stuffs), just simply use:

`make src/libwolfssl.la`

Now you have `libwolfssl.a` under `src/.libs/` directory. Simply copy it to `ketu-firmware/tools/cavp_testing/libs`. Like this:

`cp src/.libs/libwolfssl.a ketu-firmware/tools/cavp_testing/libs`

Please note that this command is for building static library for AES-GCM. If you want to use other crypto algorithms, you should re-configure.

## How to build wolfssl library archive for K2(RISC-V cross compile)

First, you should override `wc_GenerateSeed()` function inside `wolfcrypt/src/random.c`. This function tries to open a file `/dev/random`, which resulting a build error for K2(since K2 doesn't have such a file system). So, you should add `-DNO_DEV_RANDOM` to `CFLAGS` and override `wc_GenerateSeed()` function like this:

```
// line 3932:
int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    memset(output, 0, sz);
    return 0;
}
```

Then, run following commands inside wolfssl repo:

`./configure --host=riscv64-unknown-elf \
CC=riscv64-unknown-elf-gcc \
AR=riscv64-unknown-elf-ar \
AS=riscv64-unknown-elf-as \
RANLIB=/tools/sifive/release/2019.02.00/ubuntu/gcc/bin/riscv64-unknown-elf-gcc-ranlib \
LD=riscv64-unknown-elf-ld \
--disable-shared --enable-static=yes \
--enable-cryptonly=yes --enable-aesgcm=yes --disable-aesgcm-stream \
--disable-rsa --disable-dh --disable-des3 --disable-md5 --disable-sha --disable-chacha \
--disable-examples --disable-crypttests \
--enable-heapmath --disable-filesystem --enable-smallstack \
CFLAGS="-DWOLFSSL_AEAD_ONLY -DNO_DEV_RANDOM -DWOLFSSL_SIFIVE_RISC_V -march=rv64imac -mabi=lp64 -mcmodel=medany" \
host_alias=riscv64-unknown-elf`

`make src/libwolfssl.la`

`cp src/.libs/libwolfssl.a ketu-firmware/tools/cavp_testing/libs/libwolfssl_ketu.a`

You might want to change the `Makefile` inside `targets/fipstestvector/`. Check for `Makefile.wolfssl`.
