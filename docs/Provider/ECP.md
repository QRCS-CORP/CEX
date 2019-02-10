# An implementation of a system Entropy Collector Provider: ECP

## Description:
The Entropy Collection Provider is a two-stage entropy provider; it first collects system sources of entropy, and then uses them to initialize a cSHAKE pseudo-random generator. 
The first stage collects numerous caches of low entropy states; high-resolution timers, process and thread ids, the system random provider, and statistics for various hardware devices and system operations. 
These sources of entropy are compressedand used to create the cSHAKE-512 XOF functions key and customization arrays. 

## Example
```cpp
#include "ECP.h"

std::vector<byte> output(32);
ECP gen;
gen.Generate(output);
```
       
## Public Member Functions
```cpp
ECP (const ECP&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp
ECP& operator= (const ECP&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp
ECP()
```
Constructor: instantiate this class
 
```cpp
~ECP() override
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
* [NIST SP800-90B](http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf): Recommendation for the Entropy Sources Used for Random Bit Generation.
* [NIST Fips 140-2](http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf): Security Requirments For Cryptographic Modules
* [FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf): Permutation Based Hash and Extendable Output Functions 
* [NIST SP800-185](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf): SHA-3 Derived Functions
   
