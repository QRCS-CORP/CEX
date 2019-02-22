# An implementation of an cSHAKE Generator DRBG: CSG

## Overview
A DGBG based on a custom SHAKE (cSHAKE) XOF pseudo-random generaton function. This generator uses a customized SHAKE implementation along with an entropy provider to create a pseudo-random genertor with predictive resistance capabilities.
All modes of SHAKE are supported, including SHAKE-128, SHAKE-256, and the experimental SHAKE-512 and SHAKE-1024 variants.


## Initialize 
The Initialize function can take up to 3 inputs; the generator Key which is the primary key, a Nonce value which acts as a customization string, and the distribution code (Info parameter) used as the Name parameter in cSHAKE. 
The initialization parameters determine the type of underlying generator which is invoked. If only a key is used, the generator invokes a SHAKE instance. 
if both the Key and Nonce parameter are used to seed the generator, or if all three parameters contain keying material (Key, Nonce, and Info), an instance of cSHAKE is created. 

## Generate 
If an entropy provider is specified, the generate function employs a state counter, that will automatically trigger the addition of new seeding material to the cSHAKE instance after a user defined maximum threshold has been exceeded. 
Use the ReseedThreshold parameter to tune the auto re-seed interval. 
If the Parallel option is set through the constructor parameters, an SIMD parallel instance is created, this generator uses SIMD instructions to generate pseudo-random output. 
If AVX2 instructions are available on the compiling machine then the generator processes four SHAKE streams simultaneously, if AVX512 instructions are available, the generator processes eight streams. 

## Predictive Resistance: 
Predictive and backtracking resistance prevent an attacker who has gained knowledge of generator state at some time from predicting future or previous outputs from the generator. 
The optional resistance mechanism uses an entropy provider to add seed material to the generator, this new seed material is added to the current state. 
The default interval at which this reseeding occurs is once for every megabyte of output generated, but can be set using the ReseedThreshold() property; once this number of bytes or greater has been generated, new seed material is added to the generator. 
Predictive resistance is strongly recommended when producing large amounts of pseudo-random (100MB or greater).

## Implementation Notes: 
* The class constructor can either be initialized with a SHAKE mode enumeration type and entropy provider instance, or using the ShakeModes and Providers enumeration names. 
* The provider instance created using the enumeration constructor, is automatically deleted when the class is destroyed. 
* The generator can be initialized with either a SymmetricKey or SymmetricSecureKey key container class, or with a Key and optional inputs of Nonce and Info. 
* The LegalKeySizes property contains a list of the recommended key input sizes. 
* Initializing with the Nonce and Info values is recommended because this pre-initializes the SHAKE state, creating an instance of cSHAKE 
* The Generate methods can not be used until an Initialize function has been called and the generator is seeded. 
* The Update method adds new seeding material to the SHAKE state, this can be done automatically by specifying a random provider, or manually through this function. 
* The maximum amount of pseudo-random data that can be requested from the generator in a single call is fixed at 100 megabytes. 
* The maximum output from a generator instance before it must be re-initialized with a new key is fixed at 10 Gigabytes.

## Example
```cpp

#include "CSG.h"

CSG gen(ShakeModes::SHAKE256, [Providers::ACP]);
// initialize
gen.Initialize(Key, [Nonce], [Info]);
// generate bytes
gen.Generate(Output, [Offset], [Size]);
```
       
## Public Member Functions

```cpp
CSG(const CSG&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp
CSG& operator=(const CSG&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp
CSG()=delete
```
Default constructor: default constructor is restricted, this function has been deleted

```cpp
CSG(ShakeModes ShakeModeType, Providers ProviderType=Providers::ACP, bool Parallel=false)
```
Instantiate the class using a SHAKE mode, and an optional entropy source type names

```cpp
CSG(ShakeModes ShakeModeType, IProvider *Provider, bool Parallel=false)
```
Instantiate the class using a SHAKE mode type, and an optional instance pointer to an entropy source
 
```cpp
~CSG() override
```
Destructor: finalize this class

```cpp
const bool IsInitialized() override
```
Read Only: The generator is ready to produce pseudo-random

```cpp
size_t & ReseedThreshold() override
```
Read/Write: The maximum output generated before automatic auto-seed generation when using an entropy provider

```cpp
const size_t SecurityStrength() override
```
Read Only: The estimated classical security strength in bits

```cpp
void Generate(std::vector<byte> &Output) override
```
Fill a standard vector with pseudo-random bytes

```cpp
void Generate(SecureVector<byte> &Output) override
```
Fill a secure vector with pseudo-random bytes

```cpp
void Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length) override
```
Fill a standard vector with pseudo-random bytes using offset and length parameters

```cpp
void Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length) override
```
Fill a secure vector with pseudo-random bytes using offset and length parameters

```cpp
void Initialize(ISymmetricKey &Parameters) override
```
Initialize the generator with an ISymmetricKey container, containing the key and nonce, and optional info string

```cpp
void ParallelMaxDegree(size_t Degree)
```
Set the maximum number of threads allocated when using multi-threaded processing

```cpp
void Update(const std::vector<byte> &Key) override
```
Update the generators seed value

```cpp
void Update(const SecureVector<byte> &Key) override
```
Update the generators keying material with a secure vector key

## Static Public Member Functions
```cpp
static const bool HasMultiLane()
```
Read Only: The generator has AVX2 or AVX512 instructions and can process in multi-lane generation mode

```cpp
static const size_t LaneCount()
```
Read Only: The number of available SIMD lanes

## Links
* [Fips-202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf): The SHA-3 Standard
* [SP800-185](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf): SHA-3 Derived Functions 
* [Team Keccak](https://keccak.team/index.html) Homepage
