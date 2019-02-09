# HMAC

## Description:
A keyed Hash Message Authentication Code (HMAC) uses a cryptographic hash function with a secret key to verify data integrity and authenticate a message. 
Only the SHA2-256 AND SHA2-512 hash functions are supported by this implementation. 

The cryptographic strength of the HMAC depends upon the strength of the underlying hash function, the size of its hash output, and on the size and quality of the key. 
For example, when using SHA2-256 as the underlying hash function, the generator should be keyed with at least 256 bits (32 bytes) of random key. 
This functionality can be enforced by enabling the CEX_ENFORCE_KEYMIN definition in the CexConfig file, or by adding that flag to the libraries compilers directives.

## Implementation Notes: 
* This implementation supports the SHA2-256 and SHA2-512 message digests exclusively. 
* This implementation can utilize a parallelized digest instance for multi-threaded Mac calculations. 
* The generator must be initialized with a key using the Initialize function before output can be generated. 
* The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material. 
* If the Parallel parameter of the constructor is set to true, or a parallelized digest instance is loaded, passing an input block of ParallelBlockSize bytes will be processed in parallel. 
* Sequential mode block size is the underlying hash functions internal input rate-size in bytes. 
* TagSize size is the MAC functions output code-size in bytes. 
* The key size should be at least equal to the initialized MAC variants security size, 256 or 512 bits (32 and 64 bytes). 
* The Compute(Input, Output) method wraps the Update(Input, Offset, Length) and Finalize(Output, Offset) methods and should only be used on small to medium sized data./> 
* The Update(Input, Offset, Length) processes any length of message data, and is used in conjunction with the Finalize(Output, Offset) method, which completes processing and returns the finalized MAC code./> 
* After a finalizer call the MAC should be re-initialized with a new key. 

## Example
```cpp

#include "HMAC.h"

HMAC mac(SHA2Digests::SHA256);
SymmetricKey kp(Key);
mac.Initialize(kp);
mac.Update(Input, 0, Input.size());
mac.Finalize(Output, Offset);
```
       
## Public Member Functions

```cpp 
HMAC(const HMAC&)=delete 
```
Copy constructor: copy is restricted, this function has been deleted

```cpp 
HMAC& operator= (const HMAC&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp 
HMAC()=delete
```
Default constructor: default is restricted, this function has been deleted
 
```cpp 
HMAC(SHA2Digests DigestType, bool Parallel=false)
```
Initialize the class with the block cipher type enumeration name
 
```cpp 
HMAC(IDigest *Digest)
```
Initialize this class with a block cipher instance
 
```cpp
~HMAC() override
```
Destructor: finalize this class

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
void Update(const std::vector< byte > &Input, size_t InOffset, size_t Length) override
```
Update the Mac with a length of bytes

## Links

* [RFC 2104: HMAC](http://tools.ietf.org/html/rfc2104): Keyed-Hashing for Message Authentication
* [Fips 198-1](http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf): The Keyed-Hash Message Authentication Code (HMAC)
* [Fips 180-4](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf): Secure Hash Standard (SHS)
