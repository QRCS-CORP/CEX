# A Rijndael cipher using either standard modes, or extended modes of operation using a HKDF(SHA2) or cSHAKE key schedule, and increased transformation rounds: RHX

## Description:
RHX is a Rijndael implementation that can use either a standard configuration with key sizes of 16, 24, and 32 bytes (128, 192, and 256-bits), or an extended mode using key sizes of 32, 64, and 128 bytes, (256, 512, and 1024 bits). 
In extended mode, the number of transformation rounds are set to 22, 30 and 38, corresponding to the 256, 512, and 1024 input cipher key sizes. 
Increasing the number of transformation rounds processed by the ciphers transformation function creates a more diffused output, making the resulting cipher-text more resistant to some forms of cryptanalysis. 
RHX is capable of processing up to 38 rounds, that is 24 rounds more than a standard implementation of AES-256. 
 
The key schedule in RHX, and the number of transformation rounds processed are the difference between the extended mode operations, and a standard version of AES. The standard Rijndael Key Schedule processes 128, 192, and 256 bit keys, and a fixed set of transformation rounds of 10, 12, and 14, the extended version of the cipher uses 256, 512, and 1024-bit keys processing 22, 30, and 38 rounds. 
RHX extended mode can use an HMAC based Key Derivation Function; HKDF(HMAC(SHA2)) or the Keccak XOF function cSHAKE, to expand the input cipher key to create the internal round-key integer array. 
This provides better security, and allows for an implemetation to safely use an increased number of transformation rounds further strengthening the cipher. 

The cipher can also use a user-definable cipher tweak through the Info parameter of the symmetric key container, this can be used to create a unique cipher-text output. 
This tweak array is set as either the information string for HKDF, or as the cSHAKE name string.
When using the extended mode of the cipher, the minimum key size is 32 bytes (256 bits), and valid key sizes are 256, 512, and 1024 bits long. 
RHX is capable of processing up to 38 transformation rounds in extended mode; a 256-bit key uses 22 rounds, a 512-bit key 30 rounds, and a 1024-bit key is set to 38 rounds.


## Implementation Notes:
* This cipher should only be used in conjunction with an AEAD or standard cipher mode, or as an component in another construction, ex. CMAC. 
* Valid key sizes can be determined at run-time using the LegalKeySizes property. collection. 
* The internal block-size is fixed at 16 bytes (128 bits) wide. 
* The cipher can process 128, 192, and 256-bit keys in standard mode, and 256, 512, and 1024-bit keys in extended mode. 
* Transformation rounds assignments are 10, 12, and 14 in standard modes, and 22, 30, and 38 rounds with 256, 512, and 1024-bit length keys. 
* The Info parameter in a symmetric key container is a user-definable cipher tweak, this can be used to create a unique cipher-text output with a secondary secret. 
* Extended mode is set through the constructors BlockCipherExtensions parameter to either None for standard mode, or HKDF(SHA2-256), * HKDF(SHA2-512), cSHAKE256, cSHAKE512, or cSHAKE1024 for extended mode operation. 
* It is recommended that in extended mode, the key expansion functions security match the key size used; ex. with a 256-bit key use SHAKE-256, or HKDF(SHA2-512) for a 512-bit key, or SHAKE-1024 for a 1024-bit input cipher-key. 

## Example
```cpp
#include "RHX.h"

CTR cipher(Enumeration::BlockCiphers::AES);
// initialize for encryption
cipher.Initialize(true, SymmetricKey(Key, Nonce));
// encrypt a block
cipher.Transform(Input, 0, Output, 0);
```
       
## Public Member Functions

```cpp
RHX(const RHX&)=delete
```
Copy constructor: copy is restricted, this function has been deleted.

```cpp
RHX &operator= (const RHX&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp
RHX(BlockCipherExtensions CipherExtensionType=BlockCipherExtensions::None)
```
Instantiate the class with an optional block-cipher extension type.
 
```cpp
RHX(IKdf *Kdf)
```
Instantiate the class with a Key Derivation Function instance.
 
```cpp
~RHX() override
```
Destructor: finalize this class.

```cpp
const size_t BlockSize() override
```
Read Only: Unit block size of internal cipher in bytes.

```cpp
const BlockCiphers Enumeral() override
```
Read Only: The block ciphers enumeration type name.

```cpp
const bool IsEncryption() override
```
Read Only: Initialized for encryption, false for decryption.

```cpp
const bool IsInitialized() override
```
Read Only: Cipher is ready to transform data.

```cpp
const std::vector<SymmetricKeySize> &LegalKeySizes() override
```
Read Only: A list of SymmetricKeySize structures containing valid key-sizes.

```cpp
const std::string Name() override
```
Read Only: The block ciphers formal class name.

```cpp
const size_t Rounds() override
```
Read Only: The number of transformation rounds processed by the rounds function.

```cpp
const size_t StateCacheSize() override
```
Read Only: The sum size in bytes (plus some allowance for externals) of the classes persistant state.

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
Encrypt a block of bytes.

```cpp
void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override
```
Encrypt a block of bytes with offset parameters. More...
 
void 
Initialize(bool Encryption, ISymmetricKey &Parameters) override
```
Initialize the cipher with a populated SymmetricKey or SymmetricSecureKey container.

```cpp
void Transform(const std::vector<byte> &Input, std::vector<byte> &Output) override
```
Transform a block of bytes.

```cpp
void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override
```
Transform a block of bytes with offset parameters.

```cpp
void Transform512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override
```
Transform 4 blocks of bytes.

```cpp
void Transform1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override
```
Transform 8 blocks of bytes.

```cpp
void Transform2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override
```
Transform 16 blocks of bytes.

## Links

NIST AES [Fips 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
NIST [Rijndael ammended](http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf)
HKDF [RFC 5869](http://tools.ietf.org/html/rfc5869)
[FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf): Permutation Based Hash and Extendable Output Functions 
[NIST SP800-185](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf): SHA-3 Derived Functions. 
   
