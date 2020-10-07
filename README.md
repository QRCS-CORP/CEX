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
The second half is the the addition of asymmetric cryptography, with a strong focus on post-quantum security. This work is well under way, and this release contains the NTRU (NTRU Prime), RingLWE (New Hope), ModuleLWE (Kyber) and McEliece (Niederreiter) asymmetric ciphers, as well as the Dilithium, XMSS, Rainbow, and SPHINCS+ signature schemes.

Though efforts have been made towards future compatibility with other platforms, this is currently a Windows-only library, but is currently scheduled for multi-platform compatibility (Android, Linux, and possibly iOS) by the spring of 2021.
This has been tested on MSVC-2017 and MSVC-2019 in ARM/x86/x64 debug and release modes, using the MSVC and Intel compiler tool-chains, and future efforts will be made to add support for Intel/Clang and GCC compilers once testing begins on other operating systems. This project also requires OpenMP support.

Only a limited number of CPUs have been tested so far; an AMD K9, and Intel i3, i5, and i7 processors; for the moment, newer Intel and AMD cpu's are all that is supported, (testing on a wider range of hardware profiles is ongoing). 

Works with or without intrinsics, set the test project and the library to a supported instruction set to test the intrinsics enhanced implementations.
The SIMD support is set to AVX2 by default, (AVX implementations are also in place on some ciphers and protocols, set the enhanced instruction flag to your system supported set: arch:AVX2, or the minimum supported instructions arch:AVX, or None, arch:IA32). The library also has experimental AVX512 support (untested), that can be enabled through the CexConfig.h file.

The Win folder contains a visual studio test project, which tests each cipher and protocol with it's official test vectors, and has a set of digest and symmetric cipher speed tests. Make sure the project properties SIMD and OpenMP support are enabled before running the project, and for speed tests, compile in release mode.
If running the executable, the Win\Test\Vectors folder containing the cipher KAT files must be in the executables path.

For more information on the current capabilities of the library, refer to the libraries help pages.

Note: This is still an early stage in the development of this library (pre-alpha), and much of the work is formative and evolving, so stay tuned, be patient.. writing a new library is a big job! (eta is the summer of 2021).


### New in Current Release 1.0.0.8 (version A8)
* The Elliptic Curve Diffie Hellman Key exchange (EC25519)
* The Elliptic Curve Digital Signature Algorithm (ED25519)
* Integration of AES-NI 256 and 512-bit instructions
* The Rainbow signature scheme
* The 512-bit block Rijndael authenticated stream cipher RWS (end of the world cipher)
* The ChaCha derivitive CSX-512 authenticated stream cipher using 64-bit integers and a 1024-bit block, and a 512-bit key
* Changes to extended 1024-bit versions of KMAC, SHA3, and SHAKE
* The integration of SecureVector (memory locked arrays) throughout
* The addition of an IPv4/IPv6  networking stack
* The addition of a Keccak-based passphrase based KDF: SCBKDF
* The addition of a new hash-based AEAD mode: HBA
* Asymmetric ciphers and signature schemes updated to NIST-PQ Round 2 versions (updated again in November after the Round-3 versions upload)

## Contents
### Asymmetric Ciphers
* The NTRU asymmetric cipher (S-Prime and L-Prime)
* The RingLWE asymmetric cipher (New Hope -N1024/N2048)
* The Niederreiter dual form of the McEliece cipher
* The ModuleLWE asymmetric cipher (Kyber)

### Asymmetric Signature Schemes
* The Rainbow signature scheme
* The Dilithium asymmetric signature schemes
* The SPHINCS+ 256F-SHAKE128/256 asymmetric signature schemes
* The XMSS/XMSS-MT asymmetric signature schemes

### Block Ciphers
Note: Each cipher can be deployed as either the standard form (AES, Serpent), or the extended hybrid using cSHAKE or HKDF(SHA2) key expansion
* The AES-NI Hash eXtended cipher (AHX)
* The fallback Rijndael Hash eXtended cipher (RHX)
* The Serpent Hash eXtended cipher (SHX)

### Block Cipher Modes
* The Hash Based Authentication mode (HBA)
* Galois Counter authenticated block cipher Mode (GCM)
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
Note: Integrated an optional built-in authentication generator (KMAC) to each stream cipher
* The Authenticate and Encrypt and AEAD wide-block Rijndael-256 stream cipher implementation (ACS/RCS).
* The RWS authenticated stream cipher: Rijndael with a 512-bit block, running 40/80 rounds in an KMAC authenticated counter-mode stream cipher
* Threefish 256/512/1024 authenticated stream ciphers
* ChaCha256-P20 and the [experimental] CSX512 authenticated stream ciphers

### Message Digests
Note: Every message digest implementation has both parallel and sequential modes of operation
* The Blake2 256 and 512 bit variants (Blake256/Blake512)
* The SHA-3 256, 512, and (unofficial) 1024 bit variants (Keccak256/Keccak512/Keccak1024)
* The SHA2 256 and 512 bit variants (SHA256/SHA512)
* The Skein 256, 512, and 1024 bit variants(Skein256/Skein512/Skein1024)

### DRBGs
* The Block cipher Counter mode Generator using the wide-block Rijndael-256 (BCG)
* The custom cSHAKE Generator (CSG)
* The HMAC Counter Generator (HCG)

### KDFs
* Hash based Key Derivation Function (HKDF)
* Key Derivation Function Version 2 (KDF2)
* Passphrase Based Key Derivation Version 2 (PBKDF2)
* The SHAKE cost based passphrase generator (SCBKDF)
* The 128/256/512/1024 SHAKE XOF function

### MACs
* Cipher based Message Authentication Code generator (CMAC)
* Galois/Counter Message Authentication Code generator (GMAC)
* Hash based Message Authentication Code generator (HMAC)
* The Poly1305 Message Authentication Code generator (Poly1305)
* Keccak based Message Authentication Code generator (KMAC)

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
