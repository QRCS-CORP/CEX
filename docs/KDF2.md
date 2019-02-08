# KDF2

## Description:
KDF2 uses a hash digest as a pseudo-random function to produce pseudo-random output in a process known as key stretching. 

Using the same input key, and optional salt and information strings, will produce the exact same output. 

It is recommended that a pseudo-random salt value is added along with the key, this mitigates some attacks against the function. 

The minimum key size should align with the expected security level of the generator function. 

For example, when using SHA2-256 as the underlying hash function, the generator should be keyed with at least 256 bits (32 bytes) of random key. 
This functionality can be enforced by enabling the CEX_ENFORCE_KEYMIN definition in the CexConfig file, or by adding that flag to the libraries compilers directives.

## Implementation Notes: 
* This implementation only supports the SHA2-256 and SHA2-512 message digests. 
* KDF2 can be instantiated with a message digest instance, or by using the SHA2 digests enumeration type name. 
* The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material. 
* The generator must be initialized with a key using the Initialize() function before output can be generated. 
* The minimum key (passphrase) size is 4 bytes, enforcing passwords of at least 32 characters is recommended. 
* The maximum number of bytes that can be generated is the underlying digests output-size * 255. 
* The use of a salt value can strongly mitigate some attack vectors targeting the passphrase, and is highly recommended with KDF2. 
* The minimum salt size is 4 bytes, however larger pseudo-random salt values are more secure. 

## Example
```cpp

#include "KDF2.h"

// use the enumeration constructor
KDF2 kdf(Enumeration::Digests::SHA256);
// initialize
kdf.Initialize(Key, [Salt], [Info]);
// generate bytes
kdf.Generate(Output, [Offset], [Size]);
```
       
## Public Member Functions

```cpp 
KDF2(const KDF2&)=delete 
```
Copy constructor: copy is restricted, this function has been deleted

```cpp 
KDF2& operator=(const KDF2&)=delete 
```
Copy operator: copy is restricted, this function has been deleted

```cpp 
KDF2()=delete 
```
Default constructor: default is restricted, this function has been deleted

```cpp 
KDF2(SHA2Digests DigestType)
```
Instantiates an HKDF generator using a message digest type name

```cpp 
KDF2(IDigest *Digest)
```
Instantiates an HKDF generator using a message digest instance
 
 ```cpp 
~KDF2() override
 ```
Destructor: finalize this class

```cpp 
std::vector<byte> &Info()
```
Read/Write: Sets the Info value in the HKDF initialization parameters.
 
```cpp 
const bool IsInitialized() override
```
Read Only: Generator is initialized and ready to produce pseudo-random

```cpp
void Generate(std::vector<byte> &Output) override
```
Fill a standard vector with pseudo-random bytes
 
```cpp 
void Generate(SecureVector<byte> &Output) override
```
Fill a secure vector with pseudo-random bytes
 
```cpp 
void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override
```
Fill an array with pseudo-random bytes, using offset and length parameters

```cpp 
void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) override
```
Fill a secure vector with pseudo-random bytes, using offset and length parameters

```cpp 
void Initialize(ISymmetricKey &KeyParams) override
```
Initialize the generator with a SymmetricKey or SecureSymmetricKey; containing the key, and optional salt, and info string

```cpp 
void Reset() override
```
Reset the internal state; the generator must be re-initialized before it can be used again   

## Links

* ISO18033-2: [Chapter 6.2.3 KDF2](http://www.shoup.net/iso/std6.pdf)
* [RFC 6070](https://tools.ietf.org/html/rfc6070): KDF2 Test vectors
* [NIST SP80056A](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf): Recommendation for Pair-Wise Key Establishment Schemes
   
