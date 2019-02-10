# The CPU Jitter entropy Provider: CJP

## Description:
The jitter based entropy provider measures discreet timing differences in the nanosecond range of memory access requests and CPU execution time. 
Because the CPU and cache memory are continuously being accessed by various operating system and application processes, small timing differences can be observed and measured using a high-resolution timestamp. 
Delays caused by events like external thread execution, branching, cache misses, and memory movement through the processor cache levels are measured, and these small differences are collected and concentrated to produce the providers output. 
The CJP provider should not be used as the sole source of entropy for secret keys, but should be combined with other sources and concentrated to produce a key, such as the auto-seed collection provider ACP.

## Example
```cpp
#include "CJP.h"

std::vector<byte> output(32);
CJP gen;
gen.Generate(output);
```
       
## Public Member Functions
```cpp
CJP (const CJP&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp
CJP& operator= (const CJP&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp
CJP()
```
Constructor: instantiate this class
 
```cpp
~CJP() override
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
   
