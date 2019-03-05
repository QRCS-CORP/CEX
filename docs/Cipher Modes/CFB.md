# CFB: An implementation of a Cipher FeedBack Mode

## Description:
The Cipher FeedBack mode wraps a symmetric block-cipher, enabling the processing of multiple contiguous input blocks to produce a unique cipher-text output. 
Similar to CBC encryption, the chaining mechanism requires that a ciphertext block depends on preceding plaintext blocks. 
On the first block the IV is encrypted, then XOR'd with the plaintext, using the specified feedback-register number of bytes. 
The block is left-shifted by rehister-size bytes, and the ciphertext is used to fill the end of the vector. 
The second block is encrypted and XOR'd with the first encrypted block using the same register shift, and all subsequent blocks follow this pattern. 
The decryption function follows the reverse pattern; the block is decrypted with the symmetric cipher, and then XOR'd with the ciphertext from the previous block to produce the plain-text.

The encryption function of the CFB mode is limited by its dependency chain; that is, each block relies on information from the previous block, and so can not be multi-threaded. The decryption function however, is not limited by this dependency chain and can be parallelized via the use of simultaneous processing by multiple processor cores. 
This is achieved by storing the starting vector, (the encrypted bytes), from offsets within the ciphertext stream, and then processing multiple blocks of cipher-text independently across threads.

## Implementation Notes
* A cipher mode constructor can either be initialized with a block-cipher instance, or using the block ciphers enumeration type name. 
* A block-cipher instance created using the enumeration constructor, is automatically deleted when the class is destroyed. 
* The class functions are virtual, and can be accessed from an ICipherMode instance. 
* The transformation methods can not be called until the Initialize(bool, ISymmetricKey) function has been called. 
* In CFB mode, only the decryption function can be processed in parallel. 
* Parallel processing is enabled on decryption by passing an input block of at least ParallelBlockSize() to the transform; this can be disabled by setting IsParallel() to false in the ParallelProfile() accessor. 
* ParallelBlockSize() is calculated automatically based on the processor(s) L1 data cache size, this property can be user defined, but must be evenly divisible by ParallelMinimumSize(). 

## Example
```cpp
#include "CFB.h"

CFB cipher(new AES(), [RegisterSize]);
// initialize for encryption
cipher.Initialize(true, SymmetricKey(Key, Nonce));
// encrypt one block
cipher.Transform(Input, 0, Output, 0);
```
       
## Public Member Functions
```cpp
CFB(const CFB&)=delete
```
Copy constructor: copy is restricted, this function has been deleted.

```cpp
CFB &operator= (const CFB&)=delete
```
Copy operator: copy is restricted, this function has been deleted.

```cpp
CFB()=delete
```
Default constructor: default is restricted, this function has been deleted.

```cpp
CFB(BlockCiphers CipherType)
```
Initialize the Cipher Mode using a block-cipher type name.
 
```cpp
CFB(IBlockCipher* Cipher)
```
Initialize the Cipher Mode using a block-cipher instance.
 
```cpp
~CFB() override
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

