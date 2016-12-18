# CEX
The CEX Cryptographic library in C++

##Intro
###Welcome
Firstly, in it's current form, consider this as just a workspace for a personal project; it is constantly changing, and not officially published, or particularly stable.
This is also currently limited to being a Windows library only; some writing has been done anticipating future compatability with Linux, Android, and OSX, though it is not currently tested.

The library is being built in two stages; the symmetric cryptography, which consists of ciphers, hash functions, MACs, RNGs etc. This should be completed in early 2017. The second half will be the addition of asymmetric cryptography, with a strong focus on post-quantum security. When I feel the first half of the library is complete, (well, stable anyways..), I'll write an article about it, and post the link here.

All that aside, this has come a long way since the initial translation of the C# library posted here last spring; there are many additions and improvements including some very fast, very powerful symmetric cipher implementations. There are some new ideas, and new technologies, as I intend to push the envelope a little, and so am authoring this with a determination to make the fastest, most intuitive, most secure implementations possible.

##Updates

###Version 0.13: December 18, 2016
Massive update!
Added pipelined and parallelized SHA-2 implementations. 
Kdfs and Drbgs seperated and rewritten. 
Drbgs completely rewritten (added forward prediction resistance), and added an HMAC based Drbg (HMG).
XORShift+, ISAAC and VMPC MAC implementations removed, (primitives may not be secure enough or tested enough for this library).
MACs rewritten. 
Addition of a symmetric key interface with ISymmetricKey replacing old KeyParams format and unifying access across function types (Drbg, Mac, cipher and Kdf all use the same interface).
Addition of a secure key and secure memory implementations.
Three new entropy providers added: Intel RdRand/RdSeed (RDP), Cpu Jitter (CJP), and a system state entropy collector (ECP).
Some things shifted around in the namespace, and a lot of small optimizations throughout.
Documentation expanded and rewritten, now each class (brevity permitting), contains a mathematical description of the main function, a usage example, a technical overview, external links, and implementation details.
Published the libraries html help documentation and updated the links.

###Version 0.12: September 21, 2016
Added little endian counter mode ICM, updated and rewrote all block cipher modes.
Added Wide Block Vectorization (WBV) to CBC and ECB modes, (see header files for description). 
ECB and CBC-Decrypt parallelized and pipelined, CFB-Decrypt parallelized.
Updates to Salsa and ChaCha, updates to documentation, and some reorganization of code base.
Speeds are now absolutely insane; (ECB/ICM/CBC-Decrypt modes using AESNI-256, all regularly clock over 9GB per second on my 'modest' HP desktop). The block/stream cipher portion of this release is stable; (aside from bug fixes or enhancements, existing cipher modes should be constant, but new modes will soon be added).

###Version 0.11: August 12, 2016
* Fixed bug in SIMD counter staggered offsets in Salsa and ChaCha implementations
* Fixed bug in symmetric cipher Initialize() where disabling exceptions caused digest initialization to throw
* Parallel mode and CipherStream tests extended and adjusted

###Version 0.10: July 18, 2016
* Added SIMD wrappers UInt128 and UInt256
* Added intrinsics support to Twofish and Serpent (Encrypt64 and Decrypt64)
* Added intrinsics block process (mm128 -4 block) intrinsics to parallel CTR block cipher mode
* Expanded intrinsic support in AES-NI (AHX) to 4 block (Encrypt64 and Decrypt64)
* Serpent changed from outputting big endian to little endian (breaking change)
* Added intrinsics integrity tests to ParallelModeTest.
* SIMD intrinsics supported added to Serpent (SHX), Twofish (THX) and extended in Rijndael (AHX)
* Block cipher CTR mode runtime switched (cpu check) to use 128 (SSE3) and 256 (AVX) intrinsics if available
* 128 and 256 SIMD support added to ChaCha and Salsa implementations
* C++ exceptions support now optional via the ENABLE_CPPEXCEPTIONS flag in Config.h
* Added various intrinsics tests to ParallelModeTest class

###Version 0.09: July 08, 2016
* Blake2 added; 2B, 2BP, 2S, and 2SP, sequential and parallel, integrated Mac and Drbg, optional intrinsics.
* Added intrinsics to the parallelized ChaCha implementation
* Work on CpuDetect, (all intrinsics are now runtime enabled automatically).
* Set default SSE support to AVX /arch:AVX
* Work begun on intrinsics symmetric mode chain

###Version 0.08: June 04, 2016
* AES-NI added (512 key and HKDF key expansion capable).

###Versions 0.01 - 0.07: Jan 24 to June 04, 2016
* Initial translation from CEX-NET
* Updates to format and code
* First review


##Links
#####CEX .NET Article: http://www.codeproject.com/Articles/828477/Cipher-EX-V
#####API Help: http://www.vtdev.com/CEX-Plus/Help/html/index.html 
#####Homepage: http://www.vtdev.com/cexhome.html

##Disclaimer
This project contains strong cryptography, before downloading the source files, 
it is your responsibility to check if the extended symmetric cipher key lengths (512 bit and higher), and other cryptographic algorithms contained in this project are legal in your country. 
If you use this code, please do so responsibly and in accordance to law in your region.
