# The Block Cipher Interface class: IBlockCipher
       
## Public Member Functions

```cpp
IBlockCipher(const IBlockCipher&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp
IBlockCipher &operator= (const IBlockCipher&)=delete
```
Copy operator: copy is restricted, this function has been deleted.
 
```cpp
IBlockCipher()
```
Constructor: Instantiate this class.

```cpp
virtual ~IBlockCipher() noexcept
```
Destructor: finalize this class.

```cpp
virtual const size_t BlockSize()=0
```
Read Only: Unit block size of internal cipher in bytes.

```cpp
virtual const BlockCiphers Enumeral()=0
```
Read Only: The block ciphers type name.

```cpp
virtual const bool IsEncryption()=0
```
Read Only: True is initialized for encryption, false for decryption.

```cpp
virtual const bool IsInitialized()=0
```
Read Only: Cipher is ready to transform data.

```cpp
virtual const std::vector<SymmetricKeySize> &LegalKeySizes()=0
```
Read Only: A list of SymmetricKeySize structures containing valid key-sizes.

```cpp
virtual const std::string Name()=0
```
Read Only: The block ciphers class name.

```cpp
virtual const size_t Rounds()=0
```
Read Only: The number of transformation rounds processed by the transform.

```cpp
virtual const size_t StateCacheSize()=0
```
Read Only: The sum size in bytes (plus some allowance for externals) of the classes persistant state.

```cpp
virtual void DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)=0
```
Decrypt a single block of bytes.

```cpp
virtual void DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)=0
```
Decrypt a block of bytes with offset parameters.

```cpp
virtual void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)=0
```
Encrypt a block of bytes.

```cpp
virtual void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)=0
```
Encrypt a block of bytes with offset parameters.

```cpp
virtual void Initialize(bool Encryption, ISymmetricKey &Parameters)=0
```
Initialize the cipher.

```cpp
virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output)=0
```
Transform a block of bytes.

```cpp
virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)=0
```
Transform a block of bytes with offset parameters.

```cpp
virtual void Transform512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)=0
```
Transform 4 blocks of bytes.

```cpp
virtual void Transform1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)=0
```
Transform 8 blocks of bytes.

```cpp
virtual void Transform2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)=0
```
Transform 16 blocks of bytes.
