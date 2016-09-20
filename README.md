# CEX
The CEX Cryptographic library in C++

##Intro
First off, consider that this is a workspace for a personal project, it is constantly changing, and not officially published, or particularly stable.

The library is being built in two stages; the symmetric cryptography, which consists of ciphers, hash functions, MACs RNGs etc. This should be completed in early 2017. The second half will be the addition of asymmetric cryptography, with a strong focus on post-quantum security. When I feel the first half off the library is complete, (well, stable anyways..), I'll write an article about it, and post the link here.

All that aside, this has come a long way since the initial translation of the C# library posted here last spring; there are many additions and improvements including some very fast, very powerful cipher implementations. There are some new ideas, and new technologies, as I intend to push the envelope a little, and so am authoring this with a determination to make the fastest, most secure implementations possible.

##Updates
Update v1.1l, added little endian counter mode ICM, updated and rewrote all block cipher modes.
Added Wide Block Vectorization (WBV) to CBC and ECB modes, (see header files for description). 
CBC decrypt parallelized and pipelined, CFB decrypt parallelized.
Updates to Salsa and ChaCha, updates to documentation, and some reorganization of code base.
Speeds are now absolutely insane; (ECB/ICM/CBC-Decrypt modes using AESNI-256, all regularly clocks over 9GB per second on my modest HP desktop). This release is stable; (aside from bug fixes or enhancements, existing cipher modes should be constant).

Update v1.1h, Rijndael, Serpent and Twofish implementations now working with 128 and 256 bit intrinsics in multi-threaded CTR mode.
Salsa and Chacha implemented with multi-threading and 128/256 bit intrinsics

Update v1.1g, all variants of Blake2 added; 2B, 2BP, 2S, and 2SP, sequential and parallel, integrated Mac and Drbg, optional intrinsics.

Update v1.1f, AES-NI added (512 key and HKDF key expansion capable).

.NET version Article: http://www.codeproject.com/Articles/828477/Cipher-EX-V

API Help: http://www.vtdev.com/CEX-Plus/Help/index.html

Homepage: http://www.vtdev.com/cexhome.html

This project contains strong cryptography, before downloading the source files, 
it is your responsibility to check if these extended symmetric cipher key lengths (512 bit and higher), and algorithms are legal in your country. 
If you use this code, please do so responsibly and in accordance to law in your region.
