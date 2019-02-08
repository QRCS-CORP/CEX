# IKdf

## Description:
The Key Derivation Function Interface class
       
## Public Member Functions

```cpp 
IKdf (const IKdf&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp 
IKdf& operator= (const IKdf&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp 
IKdf()
```
Constructor: instantiate this class

```cpp 
virtual ~IKdf() noexcept
```
Destructor: finalize this class

```cpp 
virtual const Enumeration::Kdfs Enumeral()=0
```
Read Only: The KDF generators type name

```cpp 
virtual const bool IsInitialized()=0
```
Read Only: Generator is initialized and ready to produce pseudo-random

```cpp 
virtual const size_t MinimumKeySize()=0
```
Read Only: Minimum recommended initialization key size in bytes

```cpp 
virtual const size_t MinimumSaltSize()=0
```
Read Only: Minimum recommended salt size in bytes

```cpp 
virtual std::vector<SymmetricKeySize> LegalKeySizes() const=0
```
Read Only: Available KDF Key Sizes in SymmetricKeySize containers

```cpp 
virtual const std::string Name()=0
```
The KDF generators formal class name

```cpp 
virtual void Generate(std::vector<byte> &Output)=0
```
Fill a standard vector with pseudo-random bytes

```cpp 
virtual void Generate(SecureVector<byte> &Output)=0
```
Fill a secure vector with pseudo-random bytes

```cpp 
virtual void Generate(std::vector<byte> &Output, size_t Offset, size_t Length)=0
```
Fill an array with pseudo-random bytes, using offset and length parameters

```cpp 
virtual void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length)=0
```
Fill a secure vector with pseudo-random bytes, using offset and length parameters

```cpp 
virtual void Initialize(ISymmetricKey &KeyParams)=0
```
Initialize the generator with a SymmetricKey or SecureSymmetricKey; containing the key, and optional salt, and info string

```cpp 
virtual void Reset()=0
```
Reset the internal state; the generator must be re-initialized before it can be used again

   
