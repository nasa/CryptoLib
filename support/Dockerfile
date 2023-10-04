# CryptoLib Dockerfile
#
# docker build -t ivvitc/cryptolib:latest .
# docker push ivvitc/cryptolib:latest
#

ARG WOLFSSL_VERSION=5.6.0-stable
FROM ubuntu

ARG WOLFSSL_VERSION

RUN set -eux \
    # install deps
    && buildDeps=' \
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
        libgcrypt20-dev \
        libtool \
        make \
        python3-dev \
        python3-pip \
        unzip \
    ' \
    && apt-get update \
    && apt-get install -y --no-install-recommends $buildDeps \
    && rm -r /var/lib/apt/lists/* \

    # download source files
    && curl \
        -LS https://github.com/wolfSSL/wolfssl/archive/v${WOLFSSL_VERSION}.zip \
        -o v${WOLFSSL_VERSION}.zip \
    && unzip v${WOLFSSL_VERSION}.zip \
    && rm v${WOLFSSL_VERSION}.zip \

    # build and install wolfssl
    && cd wolfssl-${WOLFSSL_VERSION} \
    && mkdir -p build \
    && cd build \
    && cmake -DWOLFSSL_AESCCM=yes -DWOLFSSL_AESSIV=yes -DWOLFSSL_CMAC=yes .. \
    && cmake --build . \
    && make install \
    && ldconfig 

    # cleanup
    #&& cd .. \
    #&& rm -r wolfssl-${WOLFSSL_VERSION} 
    #&& apt-get purge -y --auto-remove $buildDeps

RUN pip3 install pycryptodome
