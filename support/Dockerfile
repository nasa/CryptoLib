# CryptoLib Dockerfile
#
# docker build -t ivvitc/cryptolib:latest .
# docker push ivvitc/cryptolib:latest
#

ARG WOLFSSL_VERSION=5.6.0-stable
FROM ubuntu:jammy-20240212 AS CL0

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y \
    && apt-get install -y \
        autoconf \
        automake \
        ca-certificates \
        cmake \
        curl \
        g++-multilib \
        gcc-multilib \
        gettext \
        git \
        gdb\
        lcov \
        libcurl4-openssl-dev \
        libmariadb-dev \
        libmariadb-dev-compat \
        libtool \
        make \
        python3-dev \
        python3-pip \
        unzip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install pycryptodome

FROM CL0 AS CL1
ARG GPG_ERROR_VERSION=1.50
ARG GCRYPT_VERSION=1.11.0
RUN curl \ 
    -LS https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-${GPG_ERROR_VERSION}.tar.bz2 \
    -o /tmp/libgpg-error-${GPG_ERROR_VERSION}.tar.bz2 \
    && tar -xjf /tmp/libgpg-error-${GPG_ERROR_VERSION}.tar.bz2 -C /tmp/ \
    && cd /tmp/libgpg-error-${GPG_ERROR_VERSION} \
    && ./configure \
    && make install \
    && curl \ 
        -LS https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${GCRYPT_VERSION}.tar.bz2 \
        -o /tmp/libgcrypt-${GCRYPT_VERSION}.tar.bz2 \
    && tar -xjf /tmp/libgcrypt-${GCRYPT_VERSION}.tar.bz2 -C /tmp/ \
    && cd /tmp/libgcrypt-${GCRYPT_VERSION} \
    && ./configure \
    && make install

FROM CL1 AS CL2
ARG WOLFSSL_VERSION=5.6.0-stable
RUN curl \
        -LS https://github.com/wolfSSL/wolfssl/archive/v${WOLFSSL_VERSION}.zip \
        -o v${WOLFSSL_VERSION}.zip \
    && unzip v${WOLFSSL_VERSION}.zip \
    && rm v${WOLFSSL_VERSION}.zip \
    && cd wolfssl-${WOLFSSL_VERSION} \
    && mkdir -p build \
    && cd build \
    && cmake -DWOLFSSL_AESCCM=yes -DWOLFSSL_AESSIV=yes -DWOLFSSL_CMAC=yes .. \
    && cmake --build . \
    && make install \
    && ldconfig 
