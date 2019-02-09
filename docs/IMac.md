# GMAC

## Description:
The Message Authentication Code (MAC) interface class
       
## Public Member Functions

```cpp 
Poly1305 (const Poly1305&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp 
Poly1305& operator= (const Poly1305&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp 
Poly1305()
```
Initialize the class
 
```cpp 
~Poly1305() override
```
Destructor: finalize this class More...

```cpp 
const bool IsInitialized() override
```
Read Only: The MAC generator is ready to process data

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
void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length) override
```
Update the Mac with a length of bytes
