# Usage

## Extended Procedures

Extended Procedures is currently a work in progress, and is not considered mature enough for use in operations.

To enable EP, utilize the -DCRYPTO_EPROC flag.

## Apply/Process Functions

### Crypto_TC_ApplySecurity

int32 Crypto_TC_ApplySecurity(const uint8* p_in_frame, const uint16 in_frame_length, uint8 **pp_in_frame, uint16 *p_enc_frame_len)

Performs various types of encryption on the passed input frame.  This could be, Encryption only, Authentication only, and Authenticated Encryption.

**Function inputs:**
  > **_p_in_frame_**: Frame to be encrypted.  Must match an expected format, and properly activated security association.  Proper formatting includes valid transfer frame version number.  Valid Spacecraft Id, Virtual Channel ID, Map ID, Command Control Flag, and an operational Security Association.

  > **_in_frame_length_**:  The int16 length of p_in_frame.

  > **_pp_in_frame_**: pointer to pointer of a uint8 buffer where data will be stored once fully encrypted.

  > **_p_enc_frame_len_**: pointer to uint16 that will store the length of the pointed to pp_in_frame.

**Function Return: Error / Success codes of functions:**
  > All Error Codes and Status Codes can be found within the `include/crypto_error.h` header file.



***


### Crypto_TC_ProcessSecurity

int32 Crypto_TC_ProcessSecurity(char* ingest, int* len_ingest, TC_t* tc_sdls_processed_frame)

Loads the ingest frame into the global tc_frame while performing various types of decryption.  This could be decryption only, authentication only, or authenticated decryption.

**Function Inputs:**
  > **_ingest_**:  Pointer to a character array that holds the encrypted ingest frame.

  > **_len_ingest_**:  Pointer to the integer that holds the length of the ingest frame.

  > **_tc_sdls_processed_frame_**:  Pointer to the TC_t structure that holds the header, sec_header, pdu, pdu_len, and sec_trailer.  Many of these structure types themselves that are used to break apart and give various specific information about the processed frame.

**Function Return Values:**
  > All Error Codes and Status Codes can be found within the `include/crypto_error.h` header file.


***

### Crypto_TM_ApplySecurity

int32_t Crypto_TM_ApplySecurity(SecurityAssociation_t uint8_t* pTfBuffer)

Accepts a pointer to a plain-text telemetry frame, and performs the in-place encryption or authentication while populating SDLS fields as required.  The specifics of encryption or authentication are determined by bits set within the frame header, which are then used to correlate the appropriate security association.

**Function Inputs**
  > **_pTfBuffer_**: Pointer to the transfer frame buffer which will be used for in-place encryption or authentication. 

**Function Return Values:**
  > All Error Codes and Status Codes can be found within the `include/crypto_error.h` header file.

*** 

### Crypto_TM_ProcessSecurity

int32_t Crypto_TM_ProcessSecurity(uint8_t* p_ingest, uint16_t len_ingest, uint8_t** pp_processed_frame, uint16_t* p_decrypted_length)

Performs various types of decryption on the passed input frame.  This could be, Decryption only, Authentication only, and Authenticated Decryption.

**Function inputs:**
  > **_p_ingest_**: Frame to be decrypted.  Must match an expected format, and have a properly activated security association.  Proper formatting includes valid transfer frame version number, Spacecraft Id, Virtual Channel ID, and a Security Parameter Index (SPI) that is mapped to an operational Security Association.

  > **_len_ingest_**:  The int16 length of p_ingest.

  > **_pp_processed_frame_**: pointer to pointer of a uint8 buffer where data will be stored once fully decrypted.

  > **_p_decrypted_length_**: pointer to uint16 that will store the length of the pointed to pp_processed_frame.

**Function Return: Error / Success codes of functions:**
  > All Error Codes and Status Codes can be found within the `include/crypto_error.h` header file.

***

### Crypto_AOS_ApplySecurity

int32_t Crypto_AOS_ApplySecurity(SecurityAssociation_t uint8_t* pTfBuffer)

Accepts a pointer to a plain-text telemetry frame, and performs the in-place encryption or authentication while populating SDLS fields as required.  The specifics of encryption or authentication are determined by bits set within the frame header, which are then used to correlate the appropriate security association.

**Function Inputs**
  > **_pTfBuffer_**: Pointer to the transfer frame buffer which will be used for in-place encryption or authentication. 

**Function Return Values:**
  > All Error Codes and Status Codes can be found within the `include/crypto_error.h` header file.

*** 

### Crypto_AOS_ProcessSecurity

int32_t Crypto_AOS_ProcessSecurity(uint8_t* p_ingest, uint16_t len_ingest, uint8_t** pp_processed_frame, uint16_t* p_decrypted_length)

Performs various types of decryption on the passed input frame.  This could be, Decryption only, Authentication only, and Authenticated Decryption.

**Function inputs:**
  > **_p_ingest_**: Frame to be decrypted.  Must match an expected format, and have a properly activated security association.  Proper formatting includes valid transfer frame version number, Spacecraft Id, Virtual Channel ID, and a Security Parameter Index (SPI) that is mapped to an operational Security Association.

  > **_len_ingest_**:  The int16 length of p_ingest.

  > **_pp_processed_frame_**: pointer to pointer of a uint8 buffer where data will be stored once fully decrypted.

  > **_p_decrypted_length_**: pointer to uint16 that will store the length of the pointed to pp_processed_frame.

**Function Return: Error / Success codes of functions:**
  > All Error Codes and Status Codes can be found within the `include/crypto_error.h` header file.

