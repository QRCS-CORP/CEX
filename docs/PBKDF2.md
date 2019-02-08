# PBKDF2

## Description:
PBKDF2 uses an HMAC as a pseudo-random function to process a passphrase in a time-complexity loop, producing pseudo-random output in a process known as key stretching. 
By increasing the number of iterations in which the internal hashing function is applied, the amount of time required to derive the key becomes more computationally expensive. 

A salt value can be added to the passphrase, this strongly mitigates rainbow-table based attacks on the passphrase. 

The minimum key size should align with the expected security level of the generator function. 

For example, when using SHA2-256 as the underlying hash function, the generator should be keyed with at least 256 bits (32 bytes) of random key. 
This functionality can be enforced by enabling the CEX_ENFORCE_KEYMIN definition in the CexConfig file, or by adding that flag to the libraries compilers directives.

## Implementation Notes: 
* This implementation only supports the SHA2-256 and SHA2-512 message digests. 
* PBKDF2 can be instantiated with a message digest instance, or by using a digests enumeration type name. 
* The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material. 
* The generator must be initialized with a key using the Initialize() functions before output can be generated. 
* The minimum key (passphrase) size is 4 bytes, enforcing passwords of at least 32 characters is recommended. 
* The maximum number of bytes that can be generated is the underlying digests output-size * 255. 
* The use of a salt value can strongly mitigate some attack vectors targeting the passphrase, and is highly recommended with PBKDF2. 
* The minimum salt size is 4 bytes, however larger pseudo-random salt values are more secure. 
* The default iterations count is 10000, larger values are recommended for secure server-side password hashing e.g. +20000. 

## Example
```cpp

#include "PBKDF2.h"

// set to 10,000 rounds (default: 4000)
PBKDF2 kdf(Enumeration::Digests::SHA256, 10000);
// initialize
kdf.Initialize(Key, [Salt], [Info]);
// generate bytes
kdf.Generate(Output, [Offset], [Size]);
```
       
## Public Member Functions

```cpp 
PBKDF2(const PBKDF2&)=delete 
```
Copy constructor: copy is restricted, this function has been deleted

```cpp 
PBKDF2& operator=(const PBKDF2&)=delete 
```
Copy operator: copy is restricted, this function has been deleted

```cpp 
PBKDF2()=delete 
```
Default constructor: default is restricted, this function has been deleted

```cpp 
PBKDF2(SHA2Digests DigestType, uint Iterations = 10000)
```
Instantiates an PBKDF2 generator using a message digest type name

```cpp 
KDF2(IDigest *Digest)
```
Instantiates an PBKDF2 generator using a message digest instance
 
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

* [RFC 2898](http://tools.ietf.org/html/rfc2898): PBKDF2 Specification
* [RFC 6070](https://tools.ietf.org/html/rfc6070): PBKDF2 Test vectors
* [NIST SP800-132](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf): Recommendation for Password-Based Key Derivation. 
   
