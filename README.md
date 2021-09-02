# CryptoLib

Provide a software-only solution using the CCSDS Space Data Link Security Protocol - Extended Procedures (SDLS-EP) to secure communications between a spacecraft running the core Flight System (cFS) and a ground station.

## Prerequisites

In order to build crypto the following must be installed assuming Ubuntu 18.04 LTS:
* `sudo apt install libgpg-error-dev:i386 libgcrypt20-dev:i386`

Installation on CentOS 7 requires version > 1.6 of `libgcrypt`, which must be manually installed:
```
cd ~/Downloads
export CFLAGS=-m32
wget ftp://ftp.gnupg.org/gcrypt/libgpg-error/libgpg-error-1.21.tar.bz2
tar -xf ./libgpg-error-1.21.tar.bz2
cd libgpg-error-1.21
./configure --prefix=/usr --build=i686-linux && make
sudo make install && sudo install -v -m644 -D README /usr/share/doc/libgpg-error-1.21/README
cd ~/Downloads
wget ftp://ftp.gnupg.org/gcrypt/libgcrypt/libgcrypt-1.6.5.tar.bz2
tar -xf ./libgcrypt-1.6.5.tar.bz2
cd libgcrypt-1.6.5
./configure --prefix=/usr --build=i686-linux && make
sudo make install && sudo install -v -dm755 /usr/share/doc/libgcrypt-1.6.5 && sudo install -v -m644 README doc/{README.apichanges,fips*,libgcrypt*} /usr/share/doc/libgcrypt-1.6.5
```

## Testing

The `crypto_test.py` script simply replays and verifies the test performed between the ESA (ground station) and NASA (spacecraft):
* Build cFS
  - `make`
* Run cFS
  - `make launch`
* Run `crypto_test.py`
  - `cd /components/crypto_lib/unit_test`
  - `python2 ./crypto_test.py`
  - Follow instructions provided which go through three scenarios requires restarts in between
* Stop cFS
  - `make stop`
* Restart cFS
  - `make launch` 
