![CryptoLib logo Final All orange](https://github.com/user-attachments/assets/acb15175-9ba5-44a5-ae86-c9615400fcb7)

This documentation is designed to provide information on how to build, test, and utilize the CryptoLib library.

# CryptoLib
CryptoLib provides a C-based software-only implementation of the CCSDS Space Data Link Security Protocol (SDLS), and SDLS Extended Procedures (SDLS-EP) to secure communications between a spacecraft flight software and ground station. Originally designed as a Core Flight System (cFS) spacecraft library, CryptoLib has expanded in scope to allow generic support for multiple space and ground implementations.  At its core, CryptoLib can be configured to make use of multiple encryption libraries, including WolfSSL, LibGcrypt, and JPL's Key Management and Cryptography (KMC) encryption interfaces. 

Specific communications protocols that are supported include:
> * Telecommand (TC)
> * Telemetry (TM)
> * Advanced Orbiting Systems (AOS)

CryptoLib includes a standalone module that allows for generic coupling with Ground Systems that lack SDLS support.

## Documentation

* [Environment and Building](Environment_Building.md)

* [Releases](Releases.md)

* [Testing and Validation](Testing_Validation.md)

## Usage

* [Usage](Usage.md)

## References
### Bluebook References

* [SDLS](https://public.ccsds.org/Pubs/355x0b1.pdf)

* [SDLS-EP](https://public.ccsds.org/Pubs/355x1b1.pdf)

* [CCSDS Cryptographic Algorithms](https://public.ccsds.org/Pubs/352x0b2.pdf)

### Greenbook References

* [The Application of Security to CCSDS Protocols](https://public.ccsds.org/Pubs/350x0g3.pdf)

