# The system secure random generator: CSP

## Description:
On a windows system, the RNGCryptoServiceProvider CryptGenRandom() function is used to generate output. On Android, the arc4random() function is used. All other systems (Linux, Unix), use dev/random.

## Example
```cpp
#include "CSP.h"

std::vector<byte> output(32);
CSP gen;
gen.Generate(output);
```
       
## Public Member Functions
```cpp
CSP (const CSP&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp
CSP& operator= (const CSP&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp
CSP()
```
Constructor: instantiate this class
 
```cpp
~CSP() override
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
   
