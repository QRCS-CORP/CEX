# ISymmetricCipher: The symmetric streamcipher interface class

## Public Member Functions
```cpp
IStreamCipher(const IStreamCipher&)=delete
``` 
Copy constructor: copy is restricted, this function has been deleted

```cpp
IStreamCipher& operator= (const IStreamCipher&)=delete
``` 
Copy operator: copy is restricted, this function has been deleted

```cpp
IStreamCipher()
``` 
Constructor: Instantiate this class

```cpp
virtual ~IStreamCipher ()
```
Destructor: finalize this class

```cpp
virtual const StreamCiphers Enumeral()=0
``` 
Read Only: The stream ciphers type name

```cpp
virtual const bool IsAuthenticator()=0
``` 
Read Only: Cipher has authentication enabled

```cpp
virtual const bool IsEncryption()=0
``` 
Read Only: The cipher has been initialized for encryption
```cpp
 
virtual const bool IsInitialized()=0
``` 
Read Only: Cipher is ready to transform data

```cpp
virtual const bool IsParallel()=0
``` 
Read Only: Processor parallelization availability
```cpp
 
virtual const std::vector<SymmetricKeySize> &LegalKeySizes()=0
``` 
Read Only: Array of SymmetricKeySize containers, containing legal cipher input key sizes

```cpp
virtual const std::string Name()=0
``` 
Read Only: The stream ciphers implementation name

```cpp
virtual const size_t ParallelBlockSize()=0
``` 
Read Only: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing

```cpp
virtual ParallelOptions & ParallelProfile()=0
``` 
Read/Write: Parallel and SIMD capability flags and sizes

```cpp
virtual const std::vector<byte> Tag()=0
``` 
Read Only: The current MAC tag value

```cpp
virtual const void Tag(SecureVector<byte> &Output)=0
``` 
Copy the MAC tag to a secure-vector

```cpp
virtual const size_t TagSize()=0
``` 
Read Only: The legal tag length in bytes
```cpp
 
virtual void Initialize(bool Encryption, ISymmetricKey &Parameters)=0
``` 
Initialize the cipher with an ISymmetricKey key container

```cpp
virtual void ParallelMaxDegree(size_t Degree)=0
``` 
Set the maximum number of threads allocated when using multi-threaded processing

```cpp
virtual void SetAssociatedData (const std::vector<byte> &Input, const size_t Offset, const size_t Length)=0
``` 
Add additional data to the authentication generator

```cpp
virtual void Transform (const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)=0
``` 
Encrypt/Decrypt an array of bytes with offset and length parameters
