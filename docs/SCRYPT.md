# SCRYPT

## Description:
SCRYPT is a password-based key derivation function created by Colin Percival, originally for the Tarsnap online backup service. 
SCRYPT uses a combination of an underlying message digest and the Salsa stream cipher permutation function to make it costly to perform large-scale hardware attacks by requiring large amounts of memory to generate an output key. 
Using the same input key, and optional salt, will produce the exact same output. 

It is recommended that a salt value is added along with the key, this strongly mitigates rainbow-table based attacks on the passphrase. 
The minimum key size should align with the expected security level of the generator function. 

For example, when using SHA2-256 as the underlying hash function, the generator should be keyed with at least 256 bits (32 bytes) of random key. 
This functionality can be enforced by enabling the CEX_ENFORCE_KEYMIN definition in the CexConfig file, or by adding that flag to the libraries compilers directives.

## Implementation Notes: 
* This implementation only supports the SHA2-256 and SHA2-512 message digests. 
* SCRYPT can be initialized with a message digest instance, or by using a digests enumeration type name. 
* The minimum recommended key size is the size the underlying digests output-size in bytes. 
* The use of a salt value can strongly mitigate some attack vectors targeting the key, and is highly recommended with SCRYPT. 
* The minimum salt size is 4 bytes, however larger pseudo-random salt values are more secure. 
* The generator must be initialized with a key using the Initialize() functions before output can be generated. 
* The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material. 

## Example
```cpp

#include "SCRYPT.h"

// set to 10,000 rounds (default: 4000)
SCRYPT kdf(Enumeration::Digests::SHA256, 16384, 8, 1);
// initialize
kdf.Initialize(Key, [Salt]);
// generate bytes
kdf.Generate(Output, [Offset], [Size]);
```
       
## Public Member Functions

```cpp 
SCRYPT(const KDF2&)=delete 
```
Copy constructor: copy is restricted, this function has been deleted

```cpp 
SCRYPT& operator=(const SCRYPT&)=delete 
```
Copy operator: copy is restricted, this function has been deleted

```cpp 
SCRYPT()=delete 
```
Default constructor: default is restricted, this function has been deleted

```cpp 
SCRYPT(SHA2Digests DigestType, size_t CpuCost=16384, size_t Parallelization=1)
```
Instantiates an KDF2 generator using a message digest type name

```cpp 
SCRYPT(IDigest *Digest)
```
Instantiates an KDF2 generator using a message digest instance
 
 ```cpp 
~SCRYPT() override
 ```
Destructor: finalize this class

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

* [SCRYPT](https://www.tarsnap.com/scrypt/scrypt.pdf): Stronger Key Derivation via Sequential Memory Hard Functions
* [RFC 7914](https://tools.ietf.org/html/rfc7914): The scrypt Password-Based Key Derivation Function
* Scrypt is Maximally [Memory-Hard](http://eprint.iacr.org/2016/989.pdf)
   
