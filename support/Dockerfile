# CryptoLib Dockerfile
#
# docker build -t ivvitc/cryptolib:latest .
# docker push ivvitc/cryptolib:latest
#

FROM ubuntu:20.04 AS cl0

# Install required packages
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y \
    && apt-get install -y \
        autoconf \
        cmake \
        g++-multilib \
        gcc-multilib \
        gettext \
        git \
		gdb \
        lcov \
        libcurl4-openssl-dev \
        libmariadb-dev \
        libmariadb-dev-compat \
        libgcrypt20-dev \
        libtool \
        python3-dev \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pycryptodome

# WolfSSL
FROM cl0 AS cl1
RUN cd /tmp \
    && git clone https://github.com/wolfSSL/wolfssl.git \
    && cd /tmp/wolfssl \
    && git checkout v5.6.0-stable
    
RUN mkdir /tmp/wolfssl/build \
    && cd /tmp/wolfssl/build \
    && cmake -DCMAKE_C_FLAGS="-DWOLFSSL_AESGCM_STREAM" .. \
    && make install \
    && rm -rf /tmp/wolfssl
