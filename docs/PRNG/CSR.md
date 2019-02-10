# cSHAKE based Random generator: CSR

## Description:
An implementation of an cSHAKE based PRNG. 
Uses a keyed instance of the Keccak cSHAKE XOF function to generate pseudo-random output.
This random generator is seeded automatically with an etropy provider.
Both the entropy provider and the block cipher can be selected through the constructors parameters.

## Implementation Notes: 
* Wraps the the cSHAKE Generator (CSG) DRBG implementation. 
* Uses an internal entropy provider to seed the underlying DRBG. 
* The underlying DRBG instance can be optionally multi-threaded through the constructors Parallel parameter.

## Example
```cpp
#include "CSR.h"

CSR rnd([BlockCiphers], [Providers]);
// get random int
int num = rnd.NextUInt32([Minimum], [Maximum]);
```
       
## Public Member Functions
```cpp
CSR(const CSR&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp
CSR& operator= (const CSR&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp
CSR(ShakeModes ShakeModeType = ShakeModes::SHAKE256, Providers SeedEngine = Providers::ACP)
```
Initialize this class with parameters
 
```cpp
~CSR() override
```
Destructor: finalize this class

```cpp
void Generate(std::vector<byte> &Output) override
```
Fill a standard vector with pseudo-random bytes

```cpp
void Generate(SecureVector<byte> &Output) override
```
Fill a SecureVector with pseudo-random bytes

```cpp
void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override
```
Fill a standard vector with pseudo-random bytes using offset and length parameters

```cpp
void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) override
```
Fill a SecureVector with pseudo-random bytes using offset and length parameters

```cpp
void Reset() override
```
Reset the generator instance 

## Links

* [NIST SP800-90B](http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf): Recommendation for the Entropy Sources Used for Random Bit Generation.
* [NIST Fips 140-2](http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf): Security Requirments For Cryptographic Modules
* [NIST Security Bounds](http://eprint.iacr.org/2006/379.pdf):  for the Codebook-based: Deterministic Random Bit Generator
   
