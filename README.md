# CEX
The CEX Cryptographic library in C++

Update v1.1l, added little endian counter mode ICM, updated and rewrote all block cipher modes.
Added Wide Block Vectorization (WBV) to CBC abd ECB modes, (see header files for description). 
CBC decrypt parallelized and pipelined, CFB decrypt parallelized.
Updates to Salsa and ChaCha, updates to documentation, and some reorganization of code base.
Speeds are now officially 'insane', this release is stable..

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
