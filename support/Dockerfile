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
