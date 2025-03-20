# Testing and Validation

## Version History

| Version # | Author | Revision Date | Peer Reviewer | Revision Reason |
| --------- | ------ | ------------- | ------------- | --------------- |
| Test Plan and Procedures 11/19/2021 | R. Brown, D. Cutright, S. Zemerick | 11/19/2021 | Justin Morris, John Lucas | Initial |
| 1.0   | R. Brown, D. Cutright, S. Zemerick | 12/02/2021 | Justin Morris, John Lucas | Scheduled Release |
| 1.0.2 | R. Brown, D. Cutright, S. Zemerick | 01/31/2022 | Justin Morris, John Lucas | Scheduled Release |
| 1.1.0 | R. Brown, D. Cutright, S. Zemerick | 03/11/2022 | Justin Morris, John Lucas | Scheduled Release |
| 1.1.1 | R. Brown, J. Lucas, S.Zemerick | 09/20/2022 | Justin Morris | Wiki Updates |
| 1.3.0 | R. Brown, D. Cutright | 12/13/2023 | J. Lucas | Scheduled Release | 
| 1.3.1 | R.Brown | 01/10/2024 | J. Lucas | Scheduled Documentation Refresh | 
***


## Reference Documentation

| # | Document | Title | Description |
| - | -------- | ----- | ----------- |
| 1 | CryptoLib_FY22_Task_Plan_draft01.docx | CryptoLib Task Plan, Draft 01, 10/29/2021 | Task Plan developed by both ITC and JPL MGSS |
| 2 | 2021-11-05 CryptoLib Engineering Release Draft Docs Final.pdf | CryptoLib: 1st Engineering Release and API Draft Documentation 11/05/2021 | Engineering Release, API Documentation, and Task Plan Management Document |


***

## Introduction

This Test Plan and Procedures document describes the CryptoLib V&V testing that will be performed by the NASA IV&V Independent Test Capability (ITC) Team.  The ITC Team is collaborating with the JPL AMMOS team to provide a telecommand (TC) CCSDS SDLS encryption C library.  This plan describes in detail the testing scope, testing methods, frameworks, and how the results will be managed and maintained.  This plan is meant to serve as a “living” document and will be updated as the Test Plan changes and matures.

This wiki document maintains and tracks the methods necessary to adequately test CryptoLib.  The sections herein will be used to define an approach that will be used to fully test CryptoLib's functionality in different scenarios.  These scenarios include but are not limited to, unit testing, validation testing, and system testing.  

***

## CryptoLib Introduction

The CryptoLib library is a C library with public API functions that are meant to be called from a library user. For example, for TC encryption, the user provides an unencrypted transfer frame (TF) to the Crypto_TC_ApplySecurity() function and the function returns an encrypted TF for uplinking to the spacecraft.  

***

## Testing Strategy

The Testing Strategy for each category is described below. Each category will utilize a combination of test strategies that can include: 1) Compatibility Testing, 2) Unit Testing, 3) Validation Testing, 4) System Testing, 5) Regression Testing, and 6) Static Code Analysis using [Klocwork](https://www.perforce.com/products/klocwork). 

***

## API Functionality

The API functionality will primarily be tested through Unit Tests.  Unit Tests are designed to test the inputs, outputs, and functionality of the API functions.  Also, Unit Tests will be executed automatically on the github.com server and serve as first-check regression testing for new functionality.  The Table below lists the API functions that are currently being Unit Tested.  Please note that this is a current snapshot and Unit Tests are added often. 

Each of the unit tests are named in such a manner that what is being tested is mostly distinguishable by their naming convention.  Tests can easily be listed by calling the specific unit testing application with the –lists-tests flag.  These tests will be listed in set.name fashion.  As can be seen above the current tests are being utilized to test nominal paths, and the functionality of TC_ApplySecurity when functions like CryptoInit are not called, or bad information is passed.  They are also being utilized to test that encryption is being applied properly, and that libgcrypt is being utilized in a correct manner.  

***

## Compatibility Testing

The codebase must be capable of building within the Ubuntu, and RedHat Operating Systems.

The testing of CryptoLib within the Ubuntu operating system has all been automated through the use of GitHub’s Continuous Integration and Continuous Deployment (CI/CD) capabilities.  When code is pushed to main branches, or pull requests are created, several containers are created that test various builds with differing flags used to enable different features within the software – some of which include debug builds, MySQL capabilities, and the ability to swap between LibGCrypt and KMC capabilities.  Each of these automated containers verify the different types of builds and combination of builds, and in addition to this, verify that unit tests and validation tests properly execute and pass.  Code coverage is also automatically performed to guarantee that all functionality has been properly tested within the codebase.
Redhat based tests will need to be run manually by a developer.  A KMC-centric container is in development which will allow for automated RHEL testing, however this is currently a manual process.

Pass or fail criteria is based on the ability of the codebase to be built within the respective operating systems (cmake / make), as well as the ability to run unit and validation tests (make test).  The inability to do so will result in a failure of these scenarios.

Testing begins upon the trigger of new code to a main branch of the CryptoLib repository, or upon a new pull request.  Additionally, a new tag or release of the codebase will trigger Test Entry automatically for Ubuntu through the GitHub automated CI/CD, and manual efforts for the CentOS environment.

Testing is not performed in an automated fashion within feature or bug branches within the project repository.  This testing is done manually by developers prior to merging branches, or creating pull requests.  Automated testing resumes during and after a branch’s merge.

***

### Current Tests

All Unit Testing, Performance Testing, and Validation testing files are stored in the following location:

/util/src_util/  ut_*, pt_*, et_dt_*

The results of tests are stored within the pipeline and noted on the front page of the repository when new functionality is added to the main or dev branches.

***

## Encryption / Decryption / Validation Functionality
Standard AES-256 test vectors are being generated with predefined shared keys and known inputs to ensure that the functions Crypto_TC_ApplySecurity() and Crypto_TC_ProcessSecurity() correctly utilize the libgcrypt library.  Known and existing plaintext/ciphertext test vectors will be utilized as inputs and outputs, and a comparison will be performed to verify that the Crypto_TC_ApplySecurity() function is encrypting as expectedn and that Crypto_TC_ProcessSecurity is decryping as expected.  Please note that these tests are not designed to test the libgcrypt library, but instead, test ITC’s usage and configuration of the library.  

The NIST test cases are found at [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES).  The general idea will be to make use of these vectors within a testing framework that utilizes the Crypto_TC_ApplySecurity and Crypto_TC_ProcessSecurity functions.  The vector plain text will have an appended header and FECF trailer.  The test frame vector will then be digested by these functions and the payload output compared to the cipher text.  

***

### Validation Tests

Validation testing has been automated within the project’s GitHub repository for the Ubuntu Operating System (OS).  Manual efforts are performed to verify testing within the RHEL environments.  Tests are run when code is committed to the main branches of the repository, or upon merge/pull request to these branches.

The tests should be verified as having been performed successfully within the Ubuntu, RHEL OSes.  Manual tests need to be performed within RHEL when the code undergoes a release or tag.

Tests pass if all subtests within a test set complete successfully with expected return values.  The entire test scenario is considered a failure, should any subtest within any test set has failed to successfully complete.

Tests are performed automatically when merges or commits are made to the main branches of the repository.  These automated tests are only for the Ubuntu OS.  Other operating system tests are performed manually when there is a tag or release of the codebase.

All automated test results are maintained within the project repository.  These are stored within the actions tab.  Snapshots of the repository are archived when a release or tag is generated for the repository.

Validation testing is not automatically performed within feature or bug branches of the repository.  In order for this to be accomplished, changes to the workflow must be made within the branch to include it within the CI/CD Actions.  Otherwise, these tests must be manually performed.  All developers should perform due-diligence with running tests and verifying that they successfully pass before creating a pull-request, committing to a main repository, or when merging features or bug fixes.

The validation tests make use of NIST vectors with known outputs to verify that TC_APPLYSECURITY and TC_PROCESSSECURITY generate the output that is expected via known output tests through the NIST standard, and referenced from the following page and document: [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES). 

***

## System Testing

| Item to Test | Test Description | 
| ------------ | ---------------- | 
| Ground to Spacecraft Communication | Ground -> CryptoLib -> TCP/UDP -> CryptoLib -> Spacecraft |
| Spacecraft to Ground Communication | Spacecraft -> CryptoLib -> TCP/UDP -> CryptoLib -> Ground |

This testing approach would utilize two instances of CryptoLib.  One side would make use of the library coupled with a ground station, and the second instance would make use of CryptoLib integrated within a spacecraft.  The overall test would verify the communication successfully from one instance to the other (and the reverse) through the CryptoLib software.  This testing would lay the groundwork for implementing the ability to swap out different SDLS implementations on spacecrafts and ground stations.

The test would be performed on the Ubuntu OS within two instances.  One instance being configured for ground station usage, and the second configured for the spacecraft and integrated with representative flight software.

System testing is considered to have passed, if all subtests within test sets complete successfully and return expected values from one instance to the next.  Any type of failure within any subtest or test set is considered a test failure. 

This testing will need to be manually performed upon each release or tag of the repository once the system testing has been fully implemented.

Test for a specific release will be stored within a test results directory that will be archived within that tag or release within the GitHub repository.  

***

## CCSDS SDLS Standard

CryptoLib, and its functions all assume valid frames are passed into the system.  It is up to the user or calling program calling the API to verify and validate these frames as they are passed into the library.

