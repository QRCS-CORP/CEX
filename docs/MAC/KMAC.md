# KMAC

## Description:
A keyed Keccak Message Authentication Code generator (KMAC) that uses the Keccak cryptographic permutation function with a secret key to verify data integrity and authenticate a message. 
The cryptographic strength of KMAC depends upon the strength of the rate setting of the underlying permutation function, the size of its hash output, and on the size and quality of the key. 

The minimum key size should align with the expected security level of the generator function. 
For example, KMAC256 should be keyed with at least 256 bits (32 bytes) of random key. 
This functionality can be enforced by enabling the CEX_ENFORCE_KEYMIN definition in the CexConfig file, or by adding that flag to the libraries compilers directives.

## Implementation Notes: 
* The MAC tag size is variable; changing the KmacMode will change the size of the MAC output, the selected length is stored in the TagSize accessor property. 
* Block size is the underlying Keccak permutation functions internal rate-size in bytes. 
* The generator must be initialized with a key using the Initialize function before output can be generated. 
* The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material. 
* The key size should be at least equal to the initialized MAC variants security size; 128/256/512/1024 (16/32/64/128 bytes). 
* The Compute(Input, Output) method wraps the Update(Input, Offset, Length) and Finalize(Output, Offset) methods and should only be used on small to medium sized data./> 
* The Update(Input, Offset, Length) processes any length of message data, and is used in conjunction with the Finalize(Output, Offset) method, which completes processing and returns the finalized MAC code./> 
* After a finalizer call the MAC should be re-initialized with a new key. 

## Example
```cpp

#include "KMAC.h"

KMAC mac(Enumeration::KmacModes::KMAC256);
SymmetricKey kp(Key);
mac.Initialize(kp);
mac.Update(Input, 0, Input.size());
mac.Finalize(Output, Offset);
```
       
## Public Member Functions

```cpp 
KMAC(const KMAC&)=delete 
```
Copy constructor: copy is restricted, this function has been deleted

```cpp 
KMAC& operator= (const KMAC&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp 
KMAC()=delete
```
Default constructor: default is restricted, this function has been deleted
 
```cpp 
KMAC(KmacModes KmacModeType=KmacModes::KMAC256)
```
Initialize the class with the block KMAC mode enumeration name

```cpp
~KMAC() override
```
Destructor: finalize this class

```cpp
const bool IsInitialized() override
```
Read Only: The MAC generator is ready to process data More...

```cpp
void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) override
```
Process a vector of bytes and return the MAC code

```cpp
size_t Finalize(std::vector<byte> &Output, size_t OutOffset) override
```
Completes processing and returns the MAC code in a standard vector

```cpp
size_t Finalize(SecureVector<byte> &Output, size_t OutOffset) override
```
Completes processing and returns the MAC code in a secure vector

```cpp
void Initialize(ISymmetricKey &KeyParams) override
```
Initialize the MAC generator with an ISymmetricKey key container

```cpp
void Reset() override
```
Reset internal state to the pre-initialization defaults

```cpp
void Update (const std::vector< byte > &Input, size_t InOffset, size_t Length) override
```
Update the Mac with a length of bytes

## Links

* [Fips-202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf): The SHA-3 Standard
* [SP800-185](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf): SHA-3 Derived Functions
   
