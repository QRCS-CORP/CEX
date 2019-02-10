# HMAC Counter PRNG: HCR

## Description:
An implementation of a HMAC based Counter generator PRNG. 
Uses a keyed HMAC run in counter mode (HCG Generator) to generate pseudo-random output.
This random generator is seeded automatically with an etropy provider.
Both the entropy provider and the block cipher can be selected through the constructors parameters.

## Implementation Notes: 
* Wraps the Hash based Counter Generator (HCG) DRBG implementation. 
* Can be initialized with either of the implemented SHA2 hash digests. 
* Uses an internal entropy provider to seed the underlying DRBG. 

## Example
```cpp
#include "HCR.h"

HCR rnd([SHA2Digests], [Providers]);
// get random int
int num = rnd.NextUInt32([Minimum], [Maximum]);
```
       
## Public Member Functions
```cpp
HCR(const HCR&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp
HCR& operator= (const HCR&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp
HCR(SHA2Digests DigestType = SHA2Digests::SHA512, Providers SeedEngine = Providers::ACP)
```
Initialize this class with parameters
 
```cpp
~HCR() override
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
   
