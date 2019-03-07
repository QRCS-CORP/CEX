# OFB: An implementation of a Output FeedBack Mode

## Description:
Output Feedback Mode (OFB) is a similar construction to the CFB mode, and allows encryption of various block sizes. 
It differs in that the output of the encryption block function, (rather than the ciphertext), serves as the feedback register. 
The cipher is initialized by copying the initialization vector to an internal register, prepended by zeroes. 
During a transformation, this register is encrypted by the underlying cipher into a buffer, the buffer is then XOR'd with the input message block to produce the ciphertext. 
The vector block is then rotated so that the latter half of the vector is shifted to the start of the array, and the buffer is moved to the end of the array.

## Implementation Notes
* A cipher mode constructor can either be initialized with a block cipher instance, or using the block ciphers enumeration name. 
* A block cipher instance created using the enumeration constructor, is automatically deleted when the class is destroyed. 
* The Transform functions are virtual, and can be accessed from an ICipherMode instance. 
* The DecryptBlock and EncryptBlock functions can only be accessed through the class instance. 
* The transformation methods can not be called until the Initialize(bool, ISymmetricKey) function has been called. 
* Due to block chain depenencies in OFB mode, neither the encryption or decryption functions can be processed in parallel. 

## Example
```cpp
#include "OFB.h"

OFB cipher(BlockCiphers::AES);
// initialize for encryption
cipher.Initialize(true, SymmetricKey(Key, Nonce));
// encrypt one block
cipher.Transform(Input, 0, Output, 0);
```
       
## Public Member Functions
```cpp
OFB(const OFB&)=delete
```
Copy constructor: copy is restricted, this function has been deleted.

```cpp
OFB &operator= (const OFB&)=delete
```
Copy operator: copy is restricted, this function has been deleted.

```cpp
OFB()=delete
```
Default constructor: default is restricted, this function has been deleted.

```cpp
OFB(BlockCiphers CipherType)
```
Initialize the Cipher Mode using a block-cipher type name.
 
```cpp
OFB(IBlockCipher* Cipher)
```
Initialize the Cipher Mode using a block-cipher instance.
 
```cpp
~OFB() override
```
Destructor: finalize this class.

```cpp
const size_t BlockSize() override
```
Read Only: The ciphers internal block-size in bytes.

```cpp
const BlockCiphers CipherType() override
```
Read Only: The block ciphers enumeration type name.

```cpp
IBlockCipher* Engine() override
```
Read Only: A pointer to the underlying block-cipher instance.

```cpp
const CipherModes Enumeral() override
```
Read Only: The cipher modes enumeration type name.

```cpp
const bool IsEncryption() override
```
Read Only: The operation mode, returns true if initialized for encryption, false for decryption.

```cpp
const bool IsInitialized() override
```
Read Only: The block-cipher mode has been keyed and is ready to transform data.

```cpp
const bool IsParallel() override
```
Read Only: Processor parallelization availability.

```cpp
const std::vector<SymmetricKeySize> &LegalKeySizes() override
```
Read Only: A vector of allowed cipher-mode input key byte-sizes.

```cpp
const std::string Name() override
```
Read Only: The cipher-modes formal class name.

```cpp
const size_t ParallelBlockSize() override
```
Read Only: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing.

```cpp
ParallelOptions &ParallelProfile() override
```
Read/Write: Contains parallel and SIMD capability flags and sizes.

```cpp
void DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output) override
```
Decrypt a single block of bytes.

```cpp
void DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override
```
Decrypt a block of bytes with offset parameters.

```cpp
void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output) override
```
Encrypt a single block of bytes.

```cpp
void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override
```
Encrypt a block of bytes using offset parameters.

```cpp
void Initialize(bool Encryption, ISymmetricKey &Parameters) override
```
Initialize the cipher-mode instance.

```cpp
void ParallelMaxDegree(size_t Degree) override
```
Set the maximum number of threads allocated when using multi-threaded processing.

```cpp
void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length) override
```
Transform a length of bytes with offset parameters.

## Links
NIST [SP800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf). 
Handbook of Applied Cryptography Chapter 7: [Block Ciphers](http://cacr.uwaterloo.ca/hac/about/chap7.pdf). 

