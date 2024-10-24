  #!/bin/bash -i
#
# Convenience script for CryptoLib development
# Will update Libgpg and LibGCrypt
#

sudo apt-get install -y lcov libcurl4-openssl-dev libmariadb-dev libmariadb-dev-compat python3
curl -LS https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.50.tar.bz2 -o /tmp/libgpg-error-1.50.tar.bz2 
tar -xjf /tmp/libgpg-error-1.50.tar.bz2 -C /tmp/ && cd /tmp/libgpg-error-1.50 && sudo ./configure && sudo make install 
curl -LS https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.11.0.tar.bz2 -o /tmp/libgcrypt-1.11.0.tar.bz2 
tar -xjf /tmp/libgcrypt-1.11.0.tar.bz2 -C /tmp/ && cd /tmp/libgcrypt-1.11.0 && sudo ./configure && sudo make install && sudo ldconfig    
