# SHAKE

## Description:
The SHAKE/cSHAKE family of XOF (Extended Output Function) functions use the Keccak sponge and permutation functions to generate a pseudo-random output. 
Typically SHAKE has been implemented as a message digest function, as an alternative to SHA-3, but in this implementation it is used to generate keying material like a traditional KDF.
The cSHAKE/SHAKE 128 and 256 bit modes are standard implementations, the SHAKE512 and SHAKE1024 modes are original constructs, and should be considered experimental. 

The minimum key size should align with the expected security level of the generator function. 
For example, SHAKE256 should be keyed with at least 256 bits (32 bytes) of random key. 
This functionality can be enforced by enabling the CEX_ENFORCE_KEYMIN definition in the CexConfig file, or by adding that flag to the libraries compilers directives.

## Implementation Notes: 
* The SHAKE512 and SHAKE1024 versions are unofficial variants, and should be considered as only for experimental use. 
* Initialize the Kdf using only a key for SHAKE, or use salt and info secret-keys to enable the custom [cSHAKE] variant of the function. 
* This class can be instantiated with a SHAKE mode type name (SHAKE128/256/512/1024), the default is SHAKE256. 
* The SHAKE128 and SHAKE256 modes are standard implementations, the SHAKE512 and SHAKE1024 variants are original extensions. 
* The generator must be initialized with a key using one of the Initialize() functions before output can be generated. 
* The Initialize() function can use a SymmetricKey or SymmetricSecureKey key container class, or input arrays of Key, and optional Customization and Information vectors. 
* Initializing with customization or information parameters will create a custom distribtion of the generator by pre-initalizing the state to unique values, this is recommnded. 
* The recommended total Key size is the digests internal rate-size in bytes; the minumum recommended key size is the permutations output size (SHAKE128=16, SHAKE256=32, SHAKE512=64, SHAKE1024=128 bytes. 
* The internal block sizes (the amount of input that triggers the permutation function) in bytes are: SHAKE128=168, SHAKE256=136, with SHAKE512 and SHAKE1024 both using 72 bytes. 
* The CEX_KECCAK_STRONG macro contained in the CexConfig file halves the input rate of SHAKE-1024 to 288-bits (36 bytes), to create an optionally more diffused output. 

## Example
```cpp

#include "SHAKE.h"

// initialize with a 256bit shake mode-rate
SHAKE kdf(ShakeModes::SHAKE256);
// initialize with a key for shake, or use salt and info for cshake
kdf.Initialize(Key, [Salt], [Info]);
// generate bytes
kdf.Generate(Output, [Offset], [Size]);
```
       
## Public Member Functions

```cpp 
SHAKE(const SHAKE&)=delete 
```
Copy constructor: copy is restricted, this function has been deleted

```cpp 
SHAKE& operator=(const SHAKE&)=delete 
```
Copy operator: copy is restricted, this function has been deleted

```cpp 
SHAKE()=delete 
```
Default constructor: default is restricted, this function has been deleted

```cpp 
SHAKE(ShakeModes ShakeModeType = ShakeModes::SHAKE256)
```
Instantiates an SHAKE generator using a message digest type name
 
 ```cpp 
~SHAKE() override
 ```
Destructor: finalize this class

```cpp 
const bool IsInitialized() override
```
Read Only: Generator is initialized and ready to produce pseudo-random

```cpp
void Generate(std::vector<byte> &Output) override
```
Fill a standard vector with pseudo-random bytes
 
```cpp 
void Generate(SecureVector<byte> &Output) override
```
Fill a secure vector with pseudo-random bytes
 
```cpp 
void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override
```
Fill an array with pseudo-random bytes, using offset and length parameters

```cpp 
void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) override
```
Fill a secure vector with pseudo-random bytes, using offset and length parameters

```cpp 
void Initialize(ISymmetricKey &KeyParams) override
```
Initialize the generator with a SymmetricKey or SecureSymmetricKey; containing the key, and optional salt, and info string

```cpp 
void Initialize(const std::vector<byte> &Key)
```
Initialize the SHAKE generator with a standard vector key

```cpp 
void Initialize(const SecureVector<byte> &Key)
```
Initialize the SHAKE generator with a secure vector key

```cpp 
void Initialize(const std::vector<byte> &Key, size_t Offset, size_t Length)
```
Initialize the SHAKE generator with a standard vector key, using length and offset parameters

```cpp 
void Initialize(const SecureVector<byte> &Key, size_t Offset, size_t Length)
```
Initialize the SHAKE generator with a secure vector key, using length and offset parameters

```cpp 
void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Customization)
```
Initialize the SHAKE generator with standard vector key and customization arrays

```cpp 
void Initialize(const SecureVector<byte> &Key, const SecureVector<byte> &Customization)
```
Initialize the SHAKE generator with secure vector key and customization arrays

```cpp 
void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Customization, const std::vector<byte> &Information)
```
Initialize the cSHAKE generator with key, customization, and name standard vectors

```cpp 
void Initialize(const SecureVector<byte> &Key, const SecureVector< byte > &Customization, const SecureVector<byte> &Information)
```
Initialize the cSHAKE generator with key, customization, and information secure vectors

```cpp 
void Reset() override
```
Reset the internal state; the generator must be re-initialized before it can be used again   

## Links

* [FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf): Permutation Based Hash and Extendable Output Functions 
* [NIST SP800-185](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf): SHA-3 Derived Functions. 
* [Team Keccak](https://keccak.team/index.html): Home Page
   
