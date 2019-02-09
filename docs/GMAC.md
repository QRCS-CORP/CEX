# GMAC

## Description:
Cipher-based Message Authentication Code (GMAC), is a block-cipher based message authentication code generator. 
It can use any of the block ciphers in this library to provide assurance of message authenticity and the integrity of binary data. 

GMAC used in conjunction with a secure cipher mode (CTR) and is the basis of the Galois/Counter Mode (GCM). 
When GMAC is used as a stand-alone MAC code generator, it is suitable for use in an Encrypt-then-MAC generic composition configuration, or as an inexpensive tag generator, but should not be used solely as a PRF for pseudo-random generation.

## Implementation Notes: 
* MAC return size is the underlying ciphers block-size, in this library that is always 16 bytes, this length can be truncated by the caller, but that is not recommended. 
* The recommended Key and Nonce sizes are contained in the LegalKeySizes property. 
* The key size is fixed at 16 bytes, the nonce value is variable but must be at least 12 bytes in length. 
* The generator must be initialized with a key using the Initialize function before output can be generated. 
* The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material. 
* The Compute(Input, Output) method wraps the Update(Input, Offset, Length) and Finalize(Output, Offset) methods and should only be used on small to medium sized data./> 
* The Update(Input, Offset, Length) processes any length of message data, and is used in conjunction with the Finalize(Output, Offset) method, which completes processing and returns the finalized MAC code./> 
* After a finalizer call the MAC should be re-initialized with a new key. 

## Example
```cpp

#include "GMAC.h"

GMAC mac(BlockCiphers::AES);
SymmetricKey kp(Key, Nonce);
mac.Initialize(kp);
mac.Update(Input, 0, Input.size());
mac.Finalize(Output, Offset);
```
       
## Public Member Functions

```cpp 
GMAC(const GMAC&)=delete 
```
Copy constructor: copy is restricted, this function has been deleted

```cpp 
GMAC& operator= (const GMAC&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp 
GMAC()=delete
```
Default constructor: default is restricted, this function has been deleted
 
```cpp 
GMAC(BlockCiphers CipherType)
```
Initialize the class with the block cipher type enumeration name
 
```cpp 
GMAC(IBlockCipher *Cipher)
```
Initialize this class with a block cipher instance
 
```cpp
~GMAC() override
```
Destructor: finalize this class

```cpp
const BlockCiphers CipherType()
```
Read Only: The block cipher engine type

```cpp
const bool IsInitialized() override
```
Read Only: The MAC generator is ready to process data More...

```cpp
void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) override
```
Process a vector of bytes and return the MAC code

```cpp
size_t Finalize(std::vector<byte> &Output, size_t OutOffset) override
```
Completes processing and returns the MAC code in a standard vector

```cpp
size_t Finalize(SecureVector<byte> &Output, size_t OutOffset) override
```
Completes processing and returns the MAC code in a secure vector

```cpp
void Initialize(ISymmetricKey &KeyParams) override
```
Initialize the MAC generator with an ISymmetricKey key container

```cpp
void Reset() override
```
Reset internal state to the pre-initialization defaults

```cpp
void Update (const std::vector< byte > &Input, size_t InOffset, size_t Length) override
```
Update the Mac with a length of bytes

## Links

* [NIST SP800-38B](http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf): The CMAC Mode for Authentication
* [RFC 4493](http://tools.ietf.org/html/rfc4493): The AES-GMAC Algorithm
* [NIST](http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf):  Rijndael ammended
   
