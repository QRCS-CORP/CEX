# HKDF 

## Description:
HKDF uses an HMAC as a mixing function to produce pseudo-random output in a process known as key stretching. 
HKDF has two primary functions; Expand, which expands an input key into a larger key, and Extract, which pre-processes the input key, and optional salt and info parameters into an HMAC key. 

The Extract step is called if the KKDF is initialized with the salt parameter, this compresses the input material to a key used by HMAC. 
For best possible security, the Extract step should be skipped, and HKDF initialized with a key equal in size to the desired security level, and optimally to the HMAC functions internal block-size, with the Info parameter used as a secondary source of pseudo-random key input. 

If used in this configuration, ideally the Info parameter should be sized to the hash output-size, less one byte of counter and any padding added by the hash functions finalizer. 

Using this formula the HMAC is given the maximum amount of entropy on each expansion cycle without the need to call additional permutation compressions, and the underlying hash function processes only full blocks of input. 
The minimum key size should align with the expected security level of the generator function. 
For example, when using SHA2-256 as the underlying hash function, the generator should be keyed with at least 256 bits (32 bytes) of random key. 

This functionality can be enforced by enabling the CEX_ENFORCE_KEYMIN definition in the CexConfig file, or by adding that flag to the libraries compilers directives.

## Example
```cpp

#include "HKDF.h"

// use the enumeration constructor
HKDF kdf(Enumeration::Digests::SHA256);
// initialize
kdf.Initialize(Key, [Salt], [Info]);
// generate bytes
kdf.Generate(Output, [Offset], [Size]);
```
       
## Public Member Functions

```cpp 
HKDF (const HKDF &)=delete 
```
Copy constructor: copy is restricted, this function has been deleted

```cpp 
HKDF& operator= (const HKDF &)=delete 
```
Copy operator: copy is restricted, this function has been deleted

```cpp 
HKDF ()=delete 
```
Default constructor: default is restricted, this function has been deleted

```cpp 
HKDF (SHA2Digests DigestType)
```
Instantiates an HKDF generator using a message digest type name

```cpp 
HKDF (IDigest *Digest)
```
Instantiates an HKDF generator using a message digest instance
 
 ```cpp 
~HKDF () override
 ```
Destructor: finalize this class

```cpp 
std::vector< byte > &Info ()
```
Read/Write: Sets the Info value in the HKDF initialization parameters.
 
```cpp 
const bool IsInitialized () override
```
Read Only: Generator is initialized and ready to produce pseudo-random

```cpp
void Generate (std::vector< byte > &Output) override
```
Fill a standard vector with pseudo-random bytes
 
```cpp 
void Generate (SecureVector< byte > &Output) override
```
Fill a secure vector with pseudo-random bytes
 
```cpp 
void Generate (std::vector< byte > &Output, size_t Offset, size_t Length) override
```
Fill an array with pseudo-random bytes, using offset and length parameters

```cpp 
void Generate (SecureVector< byte > &Output, size_t Offset, size_t Length) override
```
Fill a secure vector with pseudo-random bytes, using offset and length parameters

```cpp 
void Initialize (ISymmetricKey &KeyParams) override
```
Initialize the generator with a SymmetricKey or SecureSymmetricKey; containing the key, and optional salt, and info string

```cpp 
void Reset () override
```
Reset the internal state; the generator must be re-initialized before it can be used again   

## Links

* Cryptographic Extraction and Key Derivation: [The HKDF Scheme](http://eprint.iacr.org/2010/264.pdf)
* [RFC 2104](http://tools.ietf.org/html/rfc2104): HMAC: Keyed-Hashing for Message Authentication
* [RFC 5869](http://tools.ietf.org/html/rfc5869): HMAC-based Extract-and-Expand Key Derivation Function
   
