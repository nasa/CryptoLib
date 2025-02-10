# CryptoLib Dockerfile
#
# Install latest docker from PPA: https://docs.docker.com/engine/install/ubuntu/
# 
# Debugging
#   docker build -t ivvitc/cryptolib:dev .
#   docker run -it ivvitc/cryptolib:dev /bin/bash
#
# Follow multi-arch instructions: https://www.docker.com/blog/multi-arch-images/
#   docker login
#   docker buildx create --name clbuilder
#   docker buildx use clbuilder
#   docker buildx build --platform linux/amd64 -t ivvitc/cryptolib:dev --push .
#
# TODO:
#   docker buildx build --platform linux/amd64,linux/arm64 -t ivvitc/cryptolib:dev --push .
# 

ARG WOLFSSL_VERSION=5.6.0-stable
FROM ubuntu:noble-20241118.1 AS cl0

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y \
    && apt-get install -y \
        autoconf \
        automake \
        build-essential \ 
        ca-certificates \
        cmake \
        curl \
        gettext \
        git \
        gdb\
        gcc-14 \
        lcov \
        libcurl4-openssl-dev \
        libmariadb-dev \
        libmariadb-dev-compat \
        libtool \
        make \
        python3-dev \
        python3-pip \
        python3-sphinx \
        python3-sphinx-rtd-theme \
        python3-myst-parser \
        unzip \
    && rm -rf /var/lib/apt/lists/* 

RUN ldconfig \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 60 \
    && update-alternatives --install /usr/bin/gcov gcov /usr/bin/gcov-14 60

FROM cl0 AS cl1
ARG GPG_ERROR_VERSION=1.50
ARG GCRYPT_VERSION=1.11.0
RUN curl \ 
    -LS https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-${GPG_ERROR_VERSION}.tar.bz2 \
    -o /tmp/libgpg-error-${GPG_ERROR_VERSION}.tar.bz2 \
    && tar -xjf /tmp/libgpg-error-${GPG_ERROR_VERSION}.tar.bz2 -C /tmp/ \
    && cd /tmp/libgpg-error-${GPG_ERROR_VERSION} \
    && ./configure \
    && make install \
    && export LD_LIBRARY_PATH="$LD_LIBRARYPATH:/usr/local/lib" \
    && curl \ 
        -LS https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${GCRYPT_VERSION}.tar.bz2 \
        -o /tmp/libgcrypt-${GCRYPT_VERSION}.tar.bz2 \
    && tar -xjf /tmp/libgcrypt-${GCRYPT_VERSION}.tar.bz2 -C /tmp/ \
    && cd /tmp/libgcrypt-${GCRYPT_VERSION} \
    && ./configure \
    && make install \
    && ldconfig \
    && rm -rf /tmp/*

FROM cl1 AS cl2
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


