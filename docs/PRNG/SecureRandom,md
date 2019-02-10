# An implementation of a cryptographically secure pseudo-random number generator.

## Description:
An implementation of a cryptographically secure pseudo-random number generator. 
This class is an extension wrapper that uses one of the PRNG and random provider implementations. 
The PRNG and random provider type names are loaded through the constructor, instantiating internal instances of those classes and auto-initializing the base PRNG. 
The default configuration uses and AES-256 CTR mode generator (BCR), and the auto seed collection provider. 
The secure random class can use any combination of the base PRNGs and random providers.

## Implementation Notes: 
* Wraps the Counter Mode Generator (BCG) DRBG implementation. 
* Can be initialized with any of the implemented block-ciphers run in CTR mode. 
* Uses an internal entropy provider to seed the underlying DRBG. 
* The underlying DRBG instance can be optionally multi-threaded through the constructors Parallel parameter.

## Example
```cpp
#include "SecureRandom.h"

SecureRandom rnd; 
int x = rnd.NextInt32(); 
```
       
## Public Member Functions
```cpp
SecureRandom(const SecureRandom&)=delete
```
Copy constructor: copy is restricted, this function has been deleted
 
```cpp
SecureRandom& operator= (const SecureRandom&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp
SecureRandom(Prngs PrngType=Prngs::BCR, Providers ProviderType=Providers::ACP)
```
Constructor: instantiate this class and initialize the rng
 
```cpp
~SecureRandom()
```
Destructor: finalize this class

```cpp
void Fill(std::vector<ushort> &Output, size_t Offset, size_t Elements)
```
Fill a standard vector of uint16 with pseudo-random using offset and length parameters

```cpp
void Fill(SecureVector<ushort> &Output, size_t Offset, size_t Elements)
```
Fill a secure vector of uint16 with pseudo-random using offset and length parameters

```cpp
void Fill(std::vector<uint> &Output, size_t Offset, size_t Elements)
```
Fill a standard vector of uint32 with pseudo-random using offset and length parameters

```cpp
void Fill(SecureVector<uint> &Output, size_t Offset, size_t Elements)
```
Fill a secure vector of uint32 with pseudo-random using offset and length parameters

```cpp
void Fill(std::vector<ulong> &Output, size_t Offset, size_t Elements)
```
Fill a standard vector of uint64 with pseudo-random using offset and length parameters

```cpp
void Fill(SecureVector<ulong> &Output, size_t Offset, size_t Elements)
```
Fill a secure vector of uint64 with pseudo-random using offset and length parameters

```cpp
const std::string Name()
```
Read Only: The random generators implementation name

```cpp
std::vector<byte> Generate(size_t Length)
```
Return an array filled with pseudo-random bytes

```cpp
void Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
```
Fill a standard byte vector with pseudo-random bytes using offset and length parameters

```cpp
void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length)
```
Fill a secure byte vector with pseudo-random bytes using offset and length parameters

```cpp
void Generate(std::vector<byte> &Output)
```
Fill a standard vector with pseudo-random bytes

```cpp
void Generate(SecureVector<byte> &Output)
```
Fill a secure vector with pseudo-random bytes

```cpp
char NextChar()
```
Get a random char

```cpp
unsigned char NextUChar()
```
Get a random unsigned char

```cpp
double NextDouble()
```
Get a random double

```cpp
short NextInt16()
```
Get a random short integer

```cpp
short NextInt16(short Maximum)
```
Get a random short integer up to a maximum value

```cpp
short NextInt16(short Maximum, short Minimum)
```
Get a random short integer ranged between minimum and maximum sizes

```cpp
ushort NextUInt16()
```
Get a random 16bit ushort integer

```cpp
ushort NextUInt16(ushort Maximum)
```
Get a random 16bit ushort integer up to a maximum value

```cpp
ushort NextUInt16(ushort Maximum, ushort Minimum)
```
Get a random 16bit ushort integer ranged between minimum and maximum sizes

```cpp
int NextInt32()
```
Get a random 32bit integer

```cpp
int NextInt32(int Maximum)
```
Get a random 32bit integer up to a maximum value

```cpp
int NextInt32(int Maximum, int Minimum)
```
Get a random 32bit integer ranged between minimum and maximum sizes

```cpp
uint NextUInt32()
```
Get a random 32bit unsigned integer

```cpp
uint NextUInt32(uint Maximum)
```
Get a random 32bit unsigned integer up to a maximum value

```cpp
uint NextUInt32(uint Maximum, uint Minimum)
```
Get a random 32bit unsigned integer ranged between minimum and maximum sizes

```cpp
long NextInt64()
```
Get a random 64bit long integer

```cpp
long NextInt64(long Maximum)
```
Get a random 64bit long integer up to a maximum value

```cpp
long NextInt64(long Maximum, long Minimum)
```
Get a random 64bit long integer ranged between minimum and maximum sizes

```cpp
ulong NextUInt64()
```
Get a random 64bit unsigned integer

```cpp
ulong NextUInt64(ulong Maximum)
```
Get a random 64bit unsigned integer up to a maximum value

```cpp
ulong NextUInt64(ulong Maximum, ulong Minimum)
```
Get a random 64bit unsigned integer ranged between minimum and maximum sizes
