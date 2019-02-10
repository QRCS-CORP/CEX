# The Auto Collection seed Provider: ACP

## Description:
The Auto Collection Provider is a two stage entropy provider; it first collects system sources of entropy, and then uses them to initialize a cSHAKE pseudo-random generator. 
The first stage combines RdRand, cpu/memory jitter, and the system random provider, with high resolution timers and statistics for various hardware devices and system operations. 
These sources of entropy are compressedand used to create the cSHAKE-512 XOF functions key and customization arrays.

## Example
```cpp
#include "ACP.h"

std::vector<byte> output(32);
ACP gen;
gen.Generate(output);
```
       
## Public Member Functions
```cpp
ACP (const ACP&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp
ACP& operator= (const ACP&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp
ACP()
```
Constructor: instantiate this class
 
```cpp
~ACP() override
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
void Generate (std::vector<byte> &Output, size_t Offset, size_t Length) override
```

Fill a standard vector with pseudo-random bytes using offset and length parameters

```cpp
void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) override
```
Fill a SecureVector with pseudo-random bytes using offset and length parameters

```cpp
void Reset() override
```
Reset the internal state More...

## Links

* [SHA3](http://keccak.noekeon.org/Keccak-submission-3.pdf): The Keccak digest: 
* [NIST SP800-90B](http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf): Recommendation for the Entropy Sources Used for Random Bit Generation.
* [NIST Fips 140-2](http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf): Security Requirments For Cryptographic Modules
   
