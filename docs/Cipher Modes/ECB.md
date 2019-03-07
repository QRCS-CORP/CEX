# ECB: An implementation of an Electronic CodeBook Mode

## Description:
The Electronic Code Book cipher processes message input directly through the underlying block cipher. No Initialization Vector is used, and the output from each block does not effect the output of any other block. 
For this reason, ECB is not considered a secure cipher mode, and should never be used in the transformation of real data, but only for debugging and performance testing.

## Implementation Notes
* ECB is not a secure mode, and should only be used for testing, timing, or as a base class; i.e. when constructing an authenticated mode. 
* Encryption and decryption can both be pipelined (SSE3-128 or AVX-256), and multi-threaded. 
* If the system supports Parallel processing, and IsParallel() is set to true; passing an input block of ParallelBlockSize() to the transform will be auto parallelized. 
* ParallelBlockSize() is calculated automatically based on the processor(s) L1 data cache size, this property can be user defined, and must be evenly divisible by ParallelMinimumSize(). 
* The ParallelBlockSize() can be changed through the ParallelProfile() property 

## Example
```cpp
#include "ECB.h"

ECB cipher(BlockCiphers::AES);
// initialize for encryption
cipher.Initialize(true, SymmetricKey(Key));
// encrypt one block
cipher.Transform(Input, 0, Output, 0);
```
       
## Public Member Functions
```cpp
ECB(const ECB&)=delete
```
Copy constructor: copy is restricted, this function has been deleted.

```cpp
ECB &operator= (const ECB&)=delete
```
Copy operator: copy is restricted, this function has been deleted.

```cpp
ECB()=delete
```
Default constructor: default is restricted, this function has been deleted.

```cpp
ECB(BlockCiphers CipherType)
```
Initialize the Cipher Mode using a block-cipher type name.
 
```cpp
ECB(IBlockCipher* Cipher)
```
Initialize the Cipher Mode using a block-cipher instance.
 
```cpp
~ECB() override
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

