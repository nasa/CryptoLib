# CryptoLib Requirements

Note this is in draft form and is not yet traceable to the unit tests. 

# General
* CryptoLib shall provide initialization function(s) for the setup of the library.
* CryptoLib shall provide apply security functions for each supported frame type.
* CryptoLib shall provide process security functions for each supported frame type.
* CryptoLib shall provide teardown function(s) for the cleanup of the library.
* CryptoLib shall maintain separation of modules for cryptography, key management, monitoring and control, and security associations that can be configured at build time for use.
* CryptoLib shall maintain a custom option for each module type for users to develop specific implementations.
* CryptoLib shall adhere to the CCSDS Space Data Link Security standard (CCSDS 355.0-B-2) Protocl Implementation Conformance Statements (PICS).
* CryptoLib shall adhere to the CCSDS Space Data Link Security Extended Procedures standard (CCSDS 355.1-B-1) Protocol Implementation Conformance Statements (PICS).

# CCSDS SDLS PICS
* A4/1 - CryptoLib shall support the TM Space Data Link Protocol.
* A4/2 - CryptoLib shall support the TC Space Data Link Protocol.
* A4/3 - CryptoLib shall support the AOS Space Data Link Protocol.
* A5/1 - The CryptoLib cryptography module shall support encryption.
* A5/2 - The CryptoLib cryptography module shall support authentication.
* A5/3 - The CryptoLib cryptography module shall support authenticated encryption.
* A6/1 - CryptoLib shall maintain the global virtual channel ID (GVCID) as part of the security association management data.
* A6/2 - CryptoLib shall maintain the global multiplexer access point identifier (GMAP_ID) as part of the security association management data.
* A6/3 - CryptoLib shall maintain the security parameter index (SPI) identifying the security association (SA) applicable to a frame as part of the SA management data.
* A6/4 - CryptoLib shall maintain the security association service type (SA_service_type) indicating the cryptographic function(s) specified for the SA as part of the security association management data.
* A6/5 - CryptoLib shall maintain the security association sequence number length (SA_length_SN) indicating the length of the sequence number field in the security header as part of the security association management data.
* A6/6 - CryptoLib shall maintain the security association initialization vector length (SA_length_IV) indicating the length of the initialization vector field in the security header as part of the security association management data.
* A6/7 - CryptoLib shall maintain the security association pad length (SA_length_PL) indicating the length of the pad length field in the security header as part of the security association management data.
* A6/8 - CryptoLib shall maintain the security association message authentication code length (SA_length_MAC) indicating the length of the MAC field in the security trailer as part of the security association management data.
* A6/9 - CryptoLib shall maintain the security association authentication algorithm and mode of operation as part of the security association management data.
* A6/10 - CryptoLib shall maintain the security association authentication key or index that refers to the actual key as part of the security association management data.
* A6/11 - CryptoLib shall maintain the security association authentication mask parameter indicating the value of a provided bit mask that is applied against the Transfer Frame in a bitwise-AND operation to generate an Authentication Payload as part of the security association management data.
* A6/12 - CryptoLib shall maintain the security association sequence number indicating the present value of a managed anti-replay sequence counter as part of the security association management data.
* A6/13 - CryptoLib shall maintain the security association sequence window indicating the amount of deviation the receiving end will accept between the expected anti-replay sequence number in a received frame as part of the security association management data.
* A6/14 - CryptoLib shall maintain the security association encryption algorithm and mode of operation as part of the security association management data.
* A6/15 - CryptoLib shall maintain the security association encryption key or index that refers to the actual key as part of the security association management data.
* A6/16 - CryptoLib shall maintain the security association initialization vector indicating the present value of a managed initialization vector field as part of the security association management data.
* A7/1 - CryptoLib shall have apply security functions for each transfer frame type supported that contains input parameters of a payload containing the partially formatted frame and the identifiers of the Virtual Channel and the MAP channel (for TC only).
* A7/2 - CryptoLib shall have process security functions for each transfer frame type supported that contains input parameters of a payload containing the frame and the identifiers of the Virtual Channel and the MAP channel (for TC only).
* A7.1.1/1 - CryptoLib's TM apply security payload shall consist of the first octet of the transfer frame primary header to the last octet of the fixed-length protocol data unit of the TM frame.
* A7.1.1/2 - CryptoLib's TC apply security payload shall consist of the first octet of the transfer frame primary header to the last octet of the transfer frame data field.
* A7.1.1/3 - CryptoLib's AOS apply security payload shall consist of the first octet of the transfer frame primary header to the last octet of the transfer frame data field.
* A7.1.1/5 - CryptoLib's apply security functions shall confirm the managed security association data matches the global virtual channel identifier (GVCID) parameter in the partially formatted transfer frame contained in the apply security payload.
* A7.1.1/6 - CryptoLib's TC apply security function shall confirm the global multiplexer access point identifier (GMAP_ID) parameter determined by the GVCID in the partially formatted transfer frame in the TC apply security payload is valid if the virtual channel specified is using segment headers.
* A7.1.1/7 - CryptoLib's TC apply security function transfer frame data field shall be plaintext if the cryptographic algorithm is authenticated encryption.
* A7.1.1/8 - CryptoLib's TC apply security function additional authenticated data (AAD) shall be the portion from the first octet of the Authentication Payload to the octet immediately preceding the Transfer Frame Data Field.
* A7.1.1/9 - CryptoLib's TC apply security function shall encrypt the Transfer Frame Data Field if encryption is selected for the security association in use.
* A7.1.1/10 - CryptoLib's TC apply security function shall place the number of fill bytes used into the Pad Length field of the Security Header if the algorithm and mode selected for the security association in use require.
* A7.1.1/11 - CryptoLib's TC apply security function shall increment the SA's managed sequence number by one if authentication is selected for the security association in use.
* A7.1.1/12 - CryptoLib's TC apply security function shall expect the managed sequence number in the Sequence Number field of the Security header, unless the security association (SA) specified use of the Initialization Vector field of the Security header instead if authentication is selected for an SA.
* A7.1.1/13 - CryptoLib's TC apply security function shall complete the Security Header for each transfer frame if authentication is selected for the security association in use.
* A7.1.1/14 - CryptoLib's TC apply security function shall apply the security association's (SA) authentication bit mask in a bitwise-AND operation against the partial frame if authentication is selected for the SA in use.
* A7.1.1/15 - CryptoLib's TC apply security function shall compute a MAC over the authentication payload if authentication is selected for the security association in use.
* A7.1.1/16 - CryptoLib's TC apply security function shall truncate the least-significant bits of the computed MAC, if necessary, if authentication is selected for the security association in use.
* A7.1.1/18 - CryptoLib's TC apply security function shall return a unique status to the caller per error type.
* A7.1.2/1 - CryptoLib's TM process security payload shall consist of the first octet of the transfer frame primary header to the last octet of the security trailer, if present, or the last octet of the Transfer Frame Data Field.
* A7.1.2/2 - CryptoLib's TC process security payload shall consist of the first octet of the transfer frame primary header to the last octet of the security trailer, if present, or the last octet of the Transfer Frame Data Field.
* A7.1.2/3 - CryptoLib's AOS process security payload shall consist of the first octet of the transfer frame primary header to the last octet of the security trailer, if present, or the last octet of the Transfer Frame Data Field.
* A7.1.2/5 - CryptoLib's process security functions shall confirm the managed security association data matches the global virtual channel identifier (GVCID) parameter in the partially formatted transfer frame contained in the apply security payload.
* A7.1.2/6 - CryptoLib's TC process security function shall confirm the global multiplexer access point identifier (GMAP_ID) parameter determined by the GVCID in the partially formatted transfer frame in the TC process security payload is valid if the virtual channel specified is using segment headers.
* A7.1.2/7 - CryptoLib's process security functions shall discard frames with wrong security associations and report exceptions.
* A7.1.2/8 - CryptoLib's process security function transfer frame data field shall be plaintext if the cryptographic algorithm is authenticated encryption.
* A7.1.2/9 - CryptoLib's process security function additional authenticated data (AAD) shall be the portion from the first octet of the Authentication Payload to the octet immediately preceding the Transfer Frame Data Field.
* A7.1.2/10 - CryptoLib's process security function shall apply the security association's (SA) authentication bit mask in a bitwise-AND operation against the partial frame if authentication is selected for the SA in use.
* A7.1.2/12 - CryptoLib's process security function shall compute a MAC over the authentication payload if authentication is selected for the security association in use.
* A7.1.2/13 - CryptoLib's process security function shall truncate the least-significant bits of the computed MAC, if necessary, if authentication is selected for the security association in use.
* A7.1.2/14 - CryptoLib's process security function shall verify that the computed MAC matches the MAC received in the Security Trailer if authentication is selected for the security association in use.
* A7.1.2/15 - CryptoLib's process security function shall report an exception to the service user for frames in which the received frame fails MAC verification and discard those frame if authentication is selected for the SA in use.
* A7.1.2/18 - CryptoLib's process security function shall extract the received sequence number from either the Sequence Number field of the Initialization Vector field of the Security Header according to the options specified for that SA if authentication is selected for the SA in use.
* A7.1.2/19 - CryptoLib's process security function shall compare the received sequence number to the managed sequence number if authentication is selected for the SA in use.
* A7.1.2/20 - CryptoLib's process security function shall report an exception to the service user for frames in which the received sequence number is larger than the managed sequence number by a value greater than teh window defined for that SA and discard those frames if authentication is selected for the SA in use.
* A7.1.2/23 - CryptoLib's process security function shall replace the managed sequence number with the received sequence number if the frame passes verification operations and if authentication is selected for the SA in use.
* A7.1.2/25 - CryptoLib's process security function shall decrypt the Transfer Frame Data Field if encryption is selected for the SA in use.
* A7.1.2/26 - CryptoLib's process security function shall extract the count of fill bytes used from the Pad Length field of the Security Header, and remove those fill bytes from the Frame Data field to be returned if encryption is selected for the SA in use.
* A7.1.2/27 - CryptoLib's process security function shall return a unique status to the caller per error type.
* A8.1/1 - CryptoLib's security header shall consist of one mandatory security parameter index in bits 0-15.
* A8.1/2 - CryptoLib's security header may contain an option field of the initialization vector following the SPI.
* A8.1/3 - CryptoLib's security header may contain an option field of the sequence number following the initialization vector.
* A8.1/4 - CryptoLib's security header may contain an option field of the pad length following the sequence number.
* A8.2/1 - CryptoLib's security trailer shall define the presence or absence of the MAC based on a virtual channel or MAP in the security association parameters.

# CCSDS SDLS-EP PICS
* ...
