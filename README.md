<a href="https://scan.coverity.com/projects/steppenwolfe65-cex">
  <img alt="Coverity Scan Build Status" src="https://scan.coverity.com/projects/14233/badge.svg"/>
</a>

# CEX

The CEX Cryptographic library in C++

## Intro
### Welcome
CEX is being written from the ground-up as a powerful and accessible post-quantum secure cryptographic library; a flexible security model, performance-oriented, designed for ease of use, and the automation of complex tasks.

There are some new ideas, and new technologies, as I intend to push the envelope, and so am authoring this with a determination to make the fastest, most intuitive, most secure implementations possible.

This library is being built in two stages; the symmetric cryptography, which consists of ciphers, hash functions, MACs, RNGs, TRNGs etc, preliminary work has been completed as of version v1.0. 
That work is still evolving however, as improvements and additions to the symmetric cryptography will continue throughout the libraries lifetime.
The second half will be the addition of asymmetric cryptography, with a strong focus on post-quantum security. This work has begun, and this release contains the RingLWE and McEliece asymmetric ciphers.

Though efforts have been made towards future compatibility with other platforms, this is currently a Windows-only library. 
This has been tested on MSVC-2015 and MSVC-2017 in ARM/x86/x64 debug and release modes, using the MSVC and Intel compiler tool-chains, and future efforts will be made to add support for Intel/Clang and GCC compilers once testing begins on other operating systems. This project also requires OpenMP support.

Only a limited number of CPUs have been tested so far; an AMD K9, and Intel i3, i5, and i7 processors; for the moment, newer Intel and AMD cpu's are all that is supported, (testing on a wider range of hardware profiles is ongoing, if you would like to help, contact me: john at vtdev.com). 

Works with or without intrinsics, set the test project and the library to a supported instruction set to test the intrinsics implementations.
The SIMD support is set to AVX2 by default, (AVX implementations are also in place on a number of ciphers and protocols, set the enhanced instruction flag to your system supported set: arch:AVX2, or the minimum supported instructions arch:AVX, or None, arch:IA32). The library also has experimental AVX512 support (untested), that can be enabled through the CexConfig file.

The Win folder contains a visual studio test project, which tests each cipher and protocol with it's official test vectors, and has a set of digest and symmetric cipher speed tests. Make sure the project properties SIMD and OpenMP support are enabled before running the project, and for speed tests, compile in release mode.
If running the executable, the Win\Test\Vectors folder containing the cipher KAT files must be in the executables path.

For more information on the current capabilities of the library, read the Introduction to CEX paper, for implementation help, refer to the libraries help pages.

This is still an early stage in the development of this library, so stay tuned, be patient..

## Contents
### Asymmetric Ciphers
* The RingLWE asymmetric cipher
* The Niederreiter dual form of the McEliece cipher
* The ModuleLWE asymmetric cipher

### Block Ciphers
* The AES-NI HKDF eXtended cipher (AHX)
* The Rijndael HKDF eXtended cipher (RHX)
* The Serpent HKDF eXtended cipher (SHX)
* The Twofish HKDF eXtended cipher (THX)

### Block Cipher Modes
* Encrypt and Authenticate AEAD block cipher mode (EAX) 
* Galois Counter authenticated block cipher Mode (GCM)
* Offset CodeBook authenticated block cipher Mode (OCB)
* Cipher Block Chaining mode (CBC)
* Cipher FeedBack mode (CFB)
* Big-Endian integer Counter mode (CTR)
* Electronic CodeBook mode (ECB)
* Little-Endian Integer Counter Mode (ICM)
* Output FeedBack Mode (OFB)

### Block Cipher Padding
* The ISO7816 Padding Scheme
* The PKCS7 Padding Scheme
* The Trailing Bit Compliment Padding Scheme (TBC)
* The X.923 Padding Scheme

### Stream Ciphers
* ChaCha20 stream cipher
* Salsa20 stream cipher

### Message Digests
Note: Every message digest implementation has both parallel and sequential modes of operation
* The Blake2 256 and 512 bit variants (Blake256/Blake512)
* The Keccak SHA-3 256, 512, and 1024 bit variants (Keccak256/Keccak512/Keccak1024)
* The SHA2 256 and 512 bit variants (SHA256/SHA512)
* The Skein 256, 512, and 1024 bit variants(Skein256/Skein512/Skein1024)

### DRBGs
* The Block cipher Counter mode Generator (BCG)
* The message Digest Counter Generator (DCG)
* The HMAC Counter Generator (HCG)

### KDFs
* Hash based Key Derivation Function (HKDF)
* Key Derivation Function Version 2 (KDF2)
* Passphrase Based Key Derivation Version 2 (PBKDF2)
* The SCRYPT key derivation function
* The 128/256/512/1024 SHAKE XOF function

### MACs
* Cipher based Message Authentication Code generator (CMAC)
* Galois/Counter Message Authentication Code generator (GMAC)
* Hash based Message Authentication Code generator (HMAC)
* The Poly1305 Message Authentication Code generator (Poly1305)

### PRNGs
* The auto-seeded Block cipher Counter mode Rng (BCR)
* The auto-seeded message Digest Counter Generator (DCR)
* The auto-seeded HMAC Counter Generator (HCR)
* An implementation of a Passphrase Based PRNG (PBR)
* The prng extension wrapper class (SecureRandom)

### Entropy Providers
* Auto seed Collection Provider (ACP)
* CPU Jitter entropy Provider (CJP)
* Local Crypto Service Provider (CSP)
* System Entropy Collection Provider (ECP)
* Intel RdRand/RdSeed Provider (RDP)

## Trajectory
The current version is <B>1.0.0.5</B> (A5 version), which are the major, minor, patch, and release codes.
  
### Current Release 1.0.0.5 (version A5):
* The ModuleLWE asymmetric cipher
* The SHAKE Key Derivation Function
* Addition of asymmetric cipher Encapsulate/Decapsulate api
* The library is now Misra C++ 2014 compliant

### Planned Release 1.1.0.1
* RingLWE
* McEliece
* ModuleLWE
* NTRU Prime
* Picnic
* SPHINCS+

### Planned Release 1.2.0.1
* TLS
* STM-KEX
* Android/iOS/Linux compatibility
* DLL API

## History

### Version 1.0.0.4, November 11, 2017
* Added the McEliece asymmetric cipher
* Added the 1024bit Keccak digest
* Added the Poly1305 Message Authentication Code generator
* Many changes made towards future SEI-CERT and Misra compliance (Full Misra compliance by 1.0.0.5)
* Full coding standards sweep of the library
* Integration of std::array and std::unique_ptr throughout
* A full optimization cycle completed

### Version 1.0.0.3, June 30, 2017
* Added asymmetric cipher interfaces and framework
* Added RingLWE asymmetric cipher
* Added the Auto Collection seed Provider (ACP)
* Addition of the HCR prng
* Renaming of the drbgs to xCG format: BCG, DCG, and HCG; Block cipher Counter Generator, Digest and HMAC Counter Generators
* Overhaul of SecureRandom and prng classes

### Version 1.0.0.2: April 23, 2017
Last of 1.0 sweep of the symmetric library before the second half of the project engages, with thousands of changes made throughout, and the addition of (!experimental) AVX512 support.
* Added a vectorized MemUtils class, with SIMD 128/256/512 copy, clear, set-value, and xor functions.
* Integrated vectorized replacements for memcpy, xor, and memset throughout, including cipher mode support for AVX512, (I don't have a xeon to test this, maybe you can help?).
* Reformatting of headers (inline accessors removed and the override hint added).
* Many small TODOs finished, api synchronized, and formatting and documentation changes throughout.

### Version 1.0: March 28, 2017
The first official release of the library, (ciphers and protocols are now tested, documented, and ready for deployment).
* Completed Code and Help review cycles.
* Added parallelized HMAC implementation
* Added multi-threaded Tree Hashing to all Skein and Keccak digest implementations.
* Added SIMD parallelization to Skein512.
* Rewrote SHA-2 paralellized tree hashing and added support for the SHA-NI SIMD to SHA-256.
* Added a multi-threaded and SIMD parallelized implementation of the SCRYPT key derivation function.

### Version 0.14: February 26, 2017
* Added pipelined and parallelized EAX, GCM, and OCB authenticated cipher modes
* Global integration of the ParallelOptions class for auto-calculating and independant SIMD and multi-threading controls
* Addition of the GMAC message authentication generator
* Implementation of cache management and constant-time timing attack counter-measures

### Version 0.13: December 18, 2016
Massive update! License changed from MIT to GPLv3, (it had to happen sooner or later). 
Versioning changed to 0.x format, (project is not to be considered a major release until the symmetric cryptography is complete after 0.14).

* Added pipelined and parallelized SHA-2 implementations. 
* Kdfs and Drbgs seperated and rewritten. 
* Drbgs completely rewritten (added forward prediction resistance), and added an HMAC based Drbg (HMG).
* Addition of a symmetric key interface with ISymmetricKey replacing old KeyParams format and unifying access across function types (Drbg, Mac, cipher and Kdf all use the same interface).
* Addition of a secure key and secure memory implementations.
* Three new entropy providers added: Intel RdRand/RdSeed (RDP), Cpu Jitter (CJP), and a system state entropy collector (ECP).

Some things shifted around in the namespace, and a lot of small optimizations throughout.
Documentation expanded and rewritten, now each class (brevity permitting), contains a mathematical description of the main function, a usage example, a technical overview, external links, and implementation details.

### Version 0.12: September 21, 2016
* Added little endian counter mode ICM, updated and rewrote all block cipher modes.
* Added Wide Block Vectorization (WBV) to CBC and ECB modes, (see header files for description). 
* ECB and CBC-Decrypt parallelized and pipelined, CFB-Decrypt parallelized.
* Updates to Salsa and ChaCha, updates to documentation, and some reorganization of code base.

Speeds are now absolutely insane; (ECB/ICM/CBC-Decrypt modes using AESNI-256, all regularly clock over 9GB per second on my 'modest' HP desktop). The block/stream cipher portion of this release is stable; (aside from bug fixes or enhancements, existing cipher modes should be constant, but new modes will soon be added).

### Version 0.11: August 12, 2016
* Added AVX2 versions of Serpent and Twofish (Transform128, Encrypt128, and Decrypt128 functions)
* Fixed bug in SIMD counter staggered offsets in Salsa and ChaCha implementations
* Fixed bug in symmetric cipher Initialize() where disabling exceptions caused digest initialization to throw
* Parallel mode and CipherStream tests extended and adjusted

### Version 0.10: July 18, 2016
* Added SIMD wrappers UInt128 and UInt256
* Added intrinsics support to Twofish and Serpent (Transform64, Encrypt64 and Decrypt64 functions)
* Added 128/256bit intrinsics to multi-threaded CTR block-cipher mode
* Expanded intrinsic support in AES-NI (AHX) to 4 block (Encrypt64 and Decrypt64)
* Serpent changed from outputting big endian to little endian (breaking change)
* Added intrinsics integrity tests to ParallelModeTest.
* SIMD intrinsics supported added to Serpent (SHX), Twofish (THX) and extended in Rijndael (AHX)
* Block cipher CTR mode runtime switched (cpu check) to use 128 (SSE3) and 256 (AVX) intrinsics if available
* 128 and 256 SIMD support added to ChaCha and Salsa implementations
* Added various intrinsics tests to ParallelModeTest class

### Version 0.09: July 08, 2016
* Blake2 added; 2B, 2BP, 2S, and 2SP, sequential and parallel, integrated Mac and Drbg, optional intrinsics.
* Added intrinsics to the parallelized ChaCha implementation
* Work on CpuDetect, (all intrinsics are now runtime enabled automatically).
* Set default SSE support to AVX /arch:AVX
* Work begun on intrinsics symmetric mode chain

### Version 0.08: June 04, 2016
* AES-NI added (512 key and HKDF key expansion capable).

### Versions 0.01 - 0.07: Jan 24 to June 04, 2016
* Initial translation from CEX-NET
* Updates to format and code
* First review

## License
This project is licensed under the GPL version 3 (GPLv3):
https://www.gnu.org/licenses/gpl-3.0.en.html

## Links
##### API Help: http://www.vtdev.com/CEX-Plus/Help/html/index.html 
##### Introduction to CEX++ 1.0: http://www.vtdev.com/CEX-Plus/CEX_1.0.pdf
##### CEX .NET Article: http://www.codeproject.com/Articles/828477/Cipher-EX-V

## Disclaimer
This project contains strong cryptography, before downloading the source files, 
it is your responsibility to check if the extended symmetric cipher key lengths (512 bit and higher), and other cryptographic algorithms contained in this project are legal in your country. 
If you use this code, please do so responsibly and in accordance to law in your region.
