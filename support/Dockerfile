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
#   docker buildx create --name clb
#   docker buildx use clb
#   docker buildx build --platform linux/amd64,linux/arm64 -t ivvitc/cryptolib:dev --push .
# 

FROM ubuntu:noble-20250127 AS cl0
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
        libgcrypt20-dev \
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
ARG WOLFSSL_VERSION=5.7.6-stable
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

FROM cl1 AS cl2
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y \
    && apt-get install -y \
        build-essential \
        python3-dev \
        automake \
        cmake \
        git \
        flex \
        bison \
        libglib2.0-dev \
        libpixman-1-dev \
        python3-setuptools \
        cargo \
        libgtk-3-dev \
        lld-14 \
        llvm-14 \
        llvm-14-dev \
        clang-14 \
        gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev \
        libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev \
        ninja-build \
        screen \
    && rm -rf /var/lib/apt/lists/* \
    && git clone https://github.com/AFLplusplus/AFLplusplus -b v4.31c /tmp/AFLplusplus \
    && cd /tmp/AFLplusplus \
    && make distrib \
    && make install \
    && rm -rf /tmp/AFLplusplus
