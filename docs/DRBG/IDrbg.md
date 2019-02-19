# IDrbg

## Description:
The Deterministic Random Bit Generator Interface class
       
## Public Member Functions
 
```cpp 
IDrbg(const IDrbg&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp
IDrbg& operator= (const IDrbg&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp
IDrbg()
```
Constructor: instantiate this class

```cpp
virtual ~IDrbg() noexcept
```
Destructor: finalize this class

```cpp
virtual const Drbgs Enumeral()=0
```
Read Only: The Drbg generators type name More...

```cpp
virtual const bool IsInitialized()=0
```
Read Only: Generator is ready to produce random More...

```cpp
virtual std::vector<SymmetricKeySize> LegalKeySizes() const =0
```
Read Only: List of available legal key sizes
```cpp
virtual const ulong MaxOutputSize()=0
```
Read Only: The maximum number of bytes that can be generated with a generator instance

```cpp
virtual const size_t MaxRequestSize()=0
```
Read Only: The maximum number of bytes that can be generated in a single request

```cpp
virtual const size_t MaxReseedCount()=0
```
Read Only: The maximum number of times the generator can be reseeded

```cpp
virtual const std::string Name()=0
```
The Drbg generators class name

```cpp
virtual size_t &ReseedThreshold()=0
```
Read/Write: The maximum output generated between auto-seed generation when using an entropy provider

```cpp
virtual const size_t SecurityStrength()=0
```
Read Only: The security strength in bits

```cpp
virtual void Generate(std::vector<byte> &Output)=0
```
Fill a standard vector with pseudo-random bytes

```cpp
virtual void Generate(SecureVector<byte> &Output)=0
```
Fill a secure vector with pseudo-random bytes

```cpp
virtual void Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)=0
```
Fill a standard vector with pseudo-random bytes using offset and length parameters

```cpp
virtual void Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length)=0
```
Fill a secure vector with pseudo-random bytes using offset and length parameters

```cpp
virtual void Initialize(ISymmetricKey &Parameters)=0
```
Initialize the generator with a SymmetricKey structure containing the key and optional salt (Nonce) and info string (Info)

```cpp
virtual void Update(const std::vector<byte> &Key)=0
```
Update the generators keying material

```cpp
virtual void Update(const SecureVector<byte> &Key)=0
```
Update the generators keying material with a secure vector key
