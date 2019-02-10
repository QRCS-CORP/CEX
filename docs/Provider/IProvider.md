# Entropy source collectors and concentrators interface: IProvider

## Public Member Functions
```cpp
IProvider(const IProvider&)=delete
```
Copy constructor: copy is restricted, this function has been deleted

```cpp
IProvider& operator= (const IProvider&)=delete
```
Copy operator: copy is restricted, this function has been deleted
 
```cpp
IProvider()
```cpp
Constructor: Instantiate this class

```cpp
virtual ~IProvider() noexcept
```
Destructor: finalize this class

```cpp
virtual const Providers Enumeral()=0
```
Read Only: The providers type name

```cpp
virtual const bool IsAvailable()=0
```
Read Only: The entropy provider is available on this system

```cpp
virtual const std::string Name()=0
```
Read Only: The provider class name

```cpp
virtual void Generate(std::vector<byte> &Output)=0
```
Fill a standard vector with pseudo-random bytes

```cpp
virtual void Generate(SecureVector<byte> &Output)=0
```
Fill a SecureVector with pseudo-random bytes

```cpp
virtual void Generate(std::vector<byte> &Output, size_t Offset, size_t Length)=0
```
Fill a standard vector with pseudo-random bytes using offset and length parameters

```cpp
virtual void Generate (SecureVector<byte> &Output, size_t Offset, size_t Length)=0
```
Fill a SecureVector with pseudo-random bytes using offset and length parameters

```cpp
virtual ushort NextUInt16()=0
```
Get a pseudo-random unsigned 16bit integer

```cpp
virtual uint NextUInt32()=0
```
Get a pseudo-random unsigned 32bit integer

```cpp
virtual ulong NextUInt64()=0
```
Get a pseudo-random unsigned 64bit integer

```cpp
virtual void Reset()=0
```
Reset the internal state
   
