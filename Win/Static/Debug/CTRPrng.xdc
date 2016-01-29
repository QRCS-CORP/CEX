<?xml version="1.0"?><doc>
<members>
<member name="T:CEX.Exception.CryptoRandomException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptorandomexception.h" line="8">
<summary>
Wraps exceptions thrown within Pseudo Random Number Generator operations
</summary>
</member>
<member name="M:CEX.Exception.CryptoRandomException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptorandomexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoRandomException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptorandomexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoRandomException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptorandomexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:CSPPrng" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\prngs.h" line="12">
<summary>
 A Secure PRNG using RNGCryptoServiceProvider
</summary>
</member>
<member name="F:CTRPrng" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\prngs.h" line="16">
<summary>
A Symmetric Cipher Counter mode random number generator
</summary>
</member>
<member name="F:DGCPrng" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\prngs.h" line="20">
<summary>
A Digest Counter mode random number generator
</summary>
</member>
<member name="F:PPBPrng" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\prngs.h" line="24">
<summary>
An implementation of a passphrase based PKCS#5 random number generator
</summary>
</member>
<member name="F:SP20Prng" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\prngs.h" line="28">
<summary>
An implementation of a Salsa20 Counter based Prng
</summary>
</member>
<member name="T:CEX.Enumeration.Prngs" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\prngs.h" line="7">
<summary>
Pseudo Random Generators
</summary>
</member>
<member name="T:CEX.Prng.IRandom" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="13">
<summary>
Psuedo Random Number Generator interface
</summary>
</member>
<member name="M:CEX.Prng.IRandom.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="21">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.Prng.IRandom.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="26">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Prng.IRandom.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="33">
<summary>
Get: The prngs type name
</summary>
</member>
<member name="M:CEX.Prng.IRandom.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="38">
<summary>
Get: Algorithm name
</summary>
</member>
<member name="M:CEX.Prng.IRandom.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="45">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Prng.IRandom.GetBytes(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="50">
<summary>
Return an array filled with pseudo random bytes
</summary>

<param name="Size">Size of requested byte array</param>

<returns>Random byte array</returns>
</member>
<member name="M:CEX.Prng.IRandom.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="59">
<summary>
Fill an array with pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Prng.IRandom.Next" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="66">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.IRandom.Next(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="73">
<summary>
Get an pseudo random unsigned 32bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.IRandom.Next(System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="82">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.IRandom.NextLong" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="92">
<summary>
Get a pseudo random unsigned 64bit integer
</summary>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.IRandom.NextLong(System.UInt64)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="99">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.IRandom.NextLong(System.UInt64,System.UInt64)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="108">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.IRandom.Reset" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\irandom.h" line="118">
<summary>
Reset the generator instance
</summary>
</member>
<member name="F:RHX" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\blockciphers.h" line="12">
<summary>
An implementation based on the Rijndael Block Cipher, using HKDF with a SHA512 HMAC for expanded key generation
</summary>
</member>
<member name="F:SHX" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\blockciphers.h" line="16">
<summary>
The Serpent Block Cipher Extended with an HKDF Key Schedule
</summary>
</member>
<member name="F:THX" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\blockciphers.h" line="20">
<summary>
A Twofish Block Cipher Extended with an HKDF Key Schedule
</summary>
</member>
<member name="T:CEX.Enumeration.BlockCiphers" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\blockciphers.h" line="7">
<summary>
Block Ciphers
</summary>
</member>
<member name="F:CSPRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedgenerators.h" line="12">
<summary>
A Secure Seed Generator using RNGCryptoServiceProvider
</summary>
</member>
<member name="F:ISCRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedgenerators.h" line="16">
<summary>
A Secure Seed Generator using the entropy pool and an ISAAC generator
</summary>
</member>
<member name="F:XSPRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedgenerators.h" line="20">
<summary>
A (fast but less secure) Seed Generator using the entropy pool and an XorShift+ generator
</summary>
</member>
<member name="T:CEX.Enumeration.SeedGenerators" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seedgenerators.h" line="7">
<summary>
Seed Generators
</summary>
</member>
<member name="T:CEX.Exception.CryptoSymmetricCipherException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptosymmetriccipherexception.h" line="8">
<summary>
Wraps exceptions thrown within a Symmetric cipher operational context
</summary>
</member>
<member name="M:CEX.Exception.CryptoSymmetricCipherException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptosymmetriccipherexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoSymmetricCipherException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptosymmetriccipherexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoSymmetricCipherException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptosymmetriccipherexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:Blake256" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="12">
<summary>
The Blake digest with a 256 bit return size
</summary>
</member>
<member name="F:Blake512" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="16">
<summary>
The Blake digest with a 512 bit return size
</summary>
</member>
<member name="F:Keccak256" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="20">
<summary>
The SHA-3 digest based on Keccak with a 256 bit return size
</summary>
</member>
<member name="F:Keccak512" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="24">
<summary>
The SHA-3 digest based on Keccak with a 512 bit return size
</summary>
</member>
<member name="F:SHA256" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="28">
<summary>
The SHA-2 digest with a 256 bit return size
</summary>
</member>
<member name="F:SHA512" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="32">
<summary>
The SHA-2 digest with a 512 bit return size
</summary>
</member>
<member name="F:Skein256" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="36">
<summary>
The Skein digest with a 256 bit return size
</summary>
</member>
<member name="F:Skein512" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="40">
<summary>
The Skein digest with a 512 bit return size
</summary>
</member>
<member name="F:Skein1024" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="44">
<summary>
The Skein digest with a 1024 bit return size
</summary>
</member>
<member name="T:CEX.Enumeration.Digests" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\digests.h" line="7">
<summary>
Message Digests
</summary>
</member>
<member name="T:CEX.Exception.CryptoDigestException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptodigestexception.h" line="8">
<summary>
Cryptographic digest error container
</summary>
</member>
<member name="M:CEX.Exception.CryptoDigestException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptodigestexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoDigestException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptodigestexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoDigestException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptodigestexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="T:CEX.Digest.IDigest" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="13">
<summary>
Hash Digest Interface
</summary>
</member>
<member name="M:CEX.Digest.IDigest.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="21">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Digest.IDigest.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="26">
<summary>
Finalizer
</summary>
</member>
<member name="M:CEX.Digest.IDigest.BlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="33">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Digest.IDigest.DigestSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="38">
<summary>
Get: Size of returned hash value in bytes
</summary>
</member>
<member name="M:CEX.Digest.IDigest.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="43">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.IDigest.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="48">
<summary>
Get: The Digest name
</summary>
</member>
<member name="M:CEX.Digest.IDigest.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="55">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>
</member>
<member name="M:CEX.Digest.IDigest.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="64">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.IDigest.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="72">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.IDigest.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="77">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>
</member>
<member name="M:CEX.Digest.IDigest.Reset" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="87">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.IDigest.Update(System.Byte)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\idigest.h" line="92">
<summary>
Update the message digest with a single byte
</summary>

<param name="Input">Input byte</param>
</member>
<member name="T:CEX.Utility.IntUtils" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="13">
<summary>
Integer functions class
</summary>
</member>
<member name="M:CEX.Utility.IntUtils.Be32ToBytes(System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="150">
<summary>
Convert a Big Endian 32 bit word to bytes
</summary>

<param name="Word">The 32 bit word</param>
<param name="Block">The destination bytes</param>
<param name="Offset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.Be64ToBytes(System.UInt64!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="165">
<summary>
Convert a Big Endian 64 bit dword to bytes
</summary>

<param name="Word">The 64 bit word</param>
<param name="Block">The destination bytes</param>
<param name="Offset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToBe32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="191">
<summary>
Convert a byte array to a Big Endian 32 bit word
</summary>

<param name="Block">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 32 bit word in Big Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToBe64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="207">
<summary>
Convert a byte array to a Big Endian 64 bit dword
</summary>

<param name="Block">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 64 bit word in Big Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.Le32ToBytes(System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="234">
<summary>
Convert a Litthle Endian 32 bit word to bytes
</summary>

<param name="Word">The 32 bit word</param>
<param name="Block">The destination bytes</param>
<param name="Offset">Offset within the destination block</param>
</member>
<member name="M:CEX.Utility.IntUtils.Le64ToBytes(System.UInt64!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="249">
<summary>
Convert a Little Endian 64 bit dword to bytes
</summary>

<param name="Word">The 64 bit word</param>
<param name="Block">The destination bytes</param>
<param name="Offset">Offset within the destination block</param>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToLe32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="275">
<summary>
Convert a byte array to a Little Endian 32 bit word
</summary>

<param name="Block">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 32 bit word in Little Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToLe64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="291">
<summary>
Convert a byte array to a Little Endian 64 bit dword
</summary>

<param name="Block">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 64 bit word in Little Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotateLeft(System.UInt32,System.Int32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="618">
<summary>
Rotate shift an unsigned 32 bit integer to the left
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The left shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotateLeft(System.UInt64,System.Int32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="636">
<summary>
Rotate shift an unsigned 64 bit integer to the left
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The left shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotateRight(System.UInt32,System.Int32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="649">
<summary>
Rotate shift a 32 bit integer to the right
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The right shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotateRight(System.UInt64,System.Int32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="667">
<summary>
Rotate shift an unsigned 64 bit integer to the right
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The right shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.XOR32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="835">
<summary>
Block XOR 4 bytes
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="849">
<summary>
Block XOR 8 bytes
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR128(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="863">
<summary>
Block XOR 16 bytes
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR256(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="877">
<summary>
Block XOR 32 bytes
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XORBLK(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\intutils.h" line="887">
<summary>
XOR contiguous 16 byte blocks in an array.
<para>The array must be aligned to 16</para>
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
<param name="Size">The number of (16 byte block aligned) bytes to process</param>
</member>
<member name="F:Begin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seekorigin.h" line="12">
<summary>
Start at the beginning of the stream
</summary>
</member>
<member name="F:Current" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seekorigin.h" line="16">
<summary>
Start at the streams current position
</summary>
</member>
<member name="F:End" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seekorigin.h" line="20">
<summary>
Start at the end of the stream
</summary>
</member>
<member name="T:CEX.IO.SeekOrigin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\seekorigin.h" line="7">
<summary>
Seek origin position flags
</summary>
</member>
<member name="T:CEX.Exception.CryptoProcessingException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoprocessingexception.h" line="8">
<summary>
Generalized cryptographic error container
</summary>
</member>
<member name="M:CEX.Exception.CryptoProcessingException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoprocessingexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoProcessingException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoprocessingexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoProcessingException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoprocessingexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="T:CEX.IO.IByteStream" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="11">
<summary>
Data stream object interface
</summary>
</member>
<member name="M:CEX.IO.IByteStream.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="19">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="24">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.IO.IByteStream.CanRead" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="31">
<summary>
Get: The stream can be read
</summary>
</member>
<member name="M:CEX.IO.IByteStream.CanSeek" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="36">
<summary>
Get: The stream is seekable
</summary>
</member>
<member name="M:CEX.IO.IByteStream.CanWrite" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="41">
<summary>
Get: The stream can be written to
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Length" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="46">
<summary>
Get: The stream length
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Position" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="51">
<summary>
Get: The streams current position
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Close" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="58">
<summary>
Close and flush the stream
</summary>
</member>
<member name="M:CEX.IO.IByteStream.CopyTo(CEX.IO.IByteStream*)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="63">
<summary>
Copy this stream to another stream
</summary>

<param name="Destination">The destination stream</param>
</member>
<member name="M:CEX.IO.IByteStream.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="70">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Flush" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="75">
<summary>
Write the stream to disk
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Read(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="80">
<summary>
Reads a portion of the stream into the buffer
</summary>

<param name="Buffer">The output buffer receiving the bytes</param>
<param name="Offset">Offset within the output buffer at which to begin</param>
<param name="Count">The number of bytes to read</param>

<returns>The number of bytes processed</returns>
</member>
<member name="M:CEX.IO.IByteStream.ReadByte" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="91">
<summary>
Read a single byte from the stream
</summary>

<returns>The byte value</returns>
</member>
<member name="M:CEX.IO.IByteStream.Reset" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="98">
<summary>
Reset and initialize the underlying digest
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Seek(System.UInt32,&lt;unknown type&gt;)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="103">
<summary>
Seek to a position within the stream
</summary>

<param name="Offset">The offset position</param>
<param name="Origin">The starting point</param>
</member>
<member name="M:CEX.IO.IByteStream.SetLength(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="111">
<summary>
Set the length of the stream
</summary>

<param name="Offset">The desired length</param>
</member>
<member name="M:CEX.IO.IByteStream.Write(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="118">
<summary>
Writes a buffer into the stream
</summary>

<param name="Buffer">The buffer to write to the stream</param>
<param name="Offset">Offset within the output buffer at which to begin</param>
<param name="Count">The number of bytes to write</param>

<returns>The number of bytes written</returns>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if Output array is too small</exception>
</member>
<member name="M:CEX.IO.IByteStream.WriteByte(System.Byte)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ibytestream.h" line="131">
<summary>
Write a single byte from the stream
</summary>

<returns>The byte value</returns>
</member>
<member name="T:CEX.IO.MemoryStream" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="12">
<summary>
Write data to a byte array
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.CanRead" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="26">
<summary>
Get: The stream can be read
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.CanSeek" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="31">
<summary>
Get: The stream is seekable
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.CanWrite" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="36">
<summary>
Get: The stream can be written to
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.Length" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="41">
<summary>
Get: The stream length
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.Position" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="46">
<summary>
Get: The streams current position
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.ToArray" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="51">
<summary>
Get: The underlying stream
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="58">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.#ctor(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="69">
<summary>
Initialize this class; setting the streams length
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="81">
<summary>
Initialize this class; setting a byte array as the streams content
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="92">
<summary>
Initialize this class (Copy constructor); copy a portion of a byte array to the streams content
</summary>

<param name="Offset">The offset in the Data array at which to begin copying</param>
<param name="Length">The number of bytes to copy</param>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if the offset or length values are invalid</exception>
</member>
<member name="M:CEX.IO.MemoryStream.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="115">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.Close" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="124">
<summary>
Close and flush the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Not implemented exception</exception>
</member>
<member name="M:CEX.IO.MemoryStream.CopyTo(CEX.IO.IByteStream*)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="131">
<summary>
Copy this stream to another stream
</summary>

<param name="Destination">The destination stream</param>
</member>
<member name="M:CEX.IO.MemoryStream.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="138">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.Flush" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="143">
<summary>
Write the stream to disk
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Not implemented exception</exception>
</member>
<member name="M:CEX.IO.MemoryStream.Read(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="150">
<summary>
Reads a portion of the stream into the buffer
</summary>

<param name="Buffer">The output buffer receiving the bytes</param>
<param name="Offset">Offset within the output buffer at which to begin</param>
<param name="Count">The number of bytes to read</param>

<returns>The number of bytes processed</returns>
</member>
<member name="M:CEX.IO.MemoryStream.ReadByte" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="161">
<summary>
Read a single byte from the stream
</summary>

<returns>The byte value</returns>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if the output array is too short</exception>
</member>
<member name="M:CEX.IO.MemoryStream.Reset" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="170">
<summary>
Reset and initialize the underlying stream to zero
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.Seek(System.UInt32,&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="175">
<summary>
Seek to a position within the stream
</summary>

<param name="Offset">The offset position</param>
<param name="Origin">The starting point</param>
</member>
<member name="M:CEX.IO.MemoryStream.SetLength(System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="183">
<summary>
Set the length of the stream
</summary>

<param name="Offset">The desired length</param>
</member>
<member name="M:CEX.IO.MemoryStream.Write(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="190">
<summary>
Writes a buffer into the stream
</summary>

<param name="Buffer">The output buffer to write to the stream</param>
<param name="Offset">Offset within the output buffer at which to begin</param>
<param name="Count">The number of bytes to write</param>

<returns>The number of bytes processed</returns>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if Output array is too small</exception>
</member>
<member name="M:CEX.IO.MemoryStream.WriteByte(System.Byte)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\memorystream.h" line="203">
<summary>
Write a single byte from the stream
</summary>

<returns>The byte value</returns>
</member>
<member name="T:CEX.IO.StreamWriter" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamwriter.h" line="9">
<summary>
Write integer values to a byte array
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Length" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamwriter.h" line="20">
<summary>
The length of the data
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Position" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamwriter.h" line="25">
<summary>
The current position within the data
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.#ctor(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamwriter.h" line="30">
<summary>
Initialize this class
</summary>

<param name="Length">The length of the underlying stream</param>
</member>
<member name="M:CEX.IO.StreamWriter.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamwriter.h" line="42">
<summary>
Initialize this class with a byte array
</summary>

<param name="StreamData">The byte array to write data to</param>
</member>
<member name="M:CEX.IO.StreamWriter.#ctor(CEX.IO.MemoryStream*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamwriter.h" line="54">
<summary>
Initialize this class with a MemoryStream
</summary>

<param name="DataStream">The MemoryStream to write data to</param>
</member>
<member name="M:CEX.IO.StreamWriter.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamwriter.h" line="66">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamwriter.h" line="74">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.GetBytes" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamwriter.h" line="79">
<summary>
Returns the entire array of raw bytes from the stream
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.GetStream" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamwriter.h" line="84">
<summary>
Returns the base MemoryStream object
</summary>
</member>
<member name="T:CEX.IO.StreamReader" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="9">
<summary>
Methods for reading integer types from a binary stream
</summary>
</member>
<member name="M:CEX.IO.StreamReader.Length" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="20">
<summary>
The length of the data
</summary>
</member>
<member name="M:CEX.IO.StreamReader.Position" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="25">
<summary>
The current position within the data
</summary>
</member>
<member name="M:CEX.IO.StreamReader.#ctor(CEX.IO.MemoryStream*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="30">
<summary>
Initialize this class with a byte array
</summary>

<param name="DataStream">MemoryStream to read</param>
</member>
<member name="M:CEX.IO.StreamReader.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="41">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.IO.StreamReader.ReadByte" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="48">
<summary>
Read a single byte from the stream
</summary>

<returns>The byte value</returns>
</member>
<member name="M:CEX.IO.StreamReader.ReadBytes(System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="55">
<summary>
Reads a portion of the stream into the buffer
</summary>

<param name="Length">The number of bytes to read</param>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadInt16" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="64">
<summary>
Reads a 16 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadUInt16" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="71">
<summary>
Reads an unsigned 16 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadInt32" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="78">
<summary>
Reads a 32 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadUInt32" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="85">
<summary>
Reads an unsigned 32 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadInt64" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="92">
<summary>
Reads a 64 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadUInt64" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="99">
<summary>
Reads an unsigned 64 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadWord32" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="106">
<summary>
Reads an unsigned 32 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadWord64" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamreader.h" line="113">
<summary>
Reads an unsigned 64 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="T:CEX.Common.KeyParams" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="12">
<summary>
KeyParams: A Symmetric Cipher Key and Vector Container class.
</summary>
</member>
<member name="M:CEX.Common.KeyParams.Key" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="25">
<summary>
Get/Set: Cipher Key
</summary>
</member>
<member name="M:CEX.Common.KeyParams.IV" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="31">
<summary>
Get/Set: Cipher Initialization Vector
</summary>
</member>
<member name="M:CEX.Common.KeyParams.Ikm" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="37">
<summary>
Get/Set: Input Keying Material
</summary>
</member>
<member name="M:CEX.Common.KeyParams.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="44">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.Common.KeyParams.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="56">
<summary>
Initialize this class with a Cipher Key
</summary>

<param name="Key">Cipher Key</param>
</member>
<member name="M:CEX.Common.KeyParams.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="70">
<summary>
Initialize this class with a Cipher Key, and IV
</summary>

<param name="Key">Cipher Key</param>
<param name="IV">Cipher IV</param>
</member>
<member name="M:CEX.Common.KeyParams.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="84">
<summary>
Initialize this class with a Cipher Key, IV, and IKM
</summary>

<param name="Key">Cipher Key</param>
<param name="IV">Cipher IV</param>
<param name="Ikm">Input Key Material</param>
</member>
<member name="M:CEX.Common.KeyParams.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="100">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Common.KeyParams.Clone" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="108">
<summary>
Create a shallow copy of this KeyParams class
</summary>
</member>
<member name="M:CEX.Common.KeyParams.DeepCopy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="116">
<summary>
Create a deep copy of this KeyParams class
</summary>
</member>
<member name="M:CEX.Common.KeyParams.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="135">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Common.KeyParams.Equals(CEX.Common.KeyParams*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="153">
<summary>
Compare this KeyParams instance with another
</summary>

<param name="Obj">KeyParams to compare</param>

<returns>Returns true if equal</returns>
</member>
<member name="M:CEX.Common.KeyParams.DeSerialize(CEX.IO.MemoryStream*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="172">
<summary>
Deserialize a KeyParams class
</summary>

<param name="KeyStream">Stream containing the KeyParams data</param>

<returns>A populated KeyParams class</returns>
</member>
<member name="M:CEX.Common.KeyParams.Serialize(CEX.Common.KeyParams*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\keyparams.h" line="199">
<summary>
Serialize a KeyParams class
</summary>

<param name="KeyObj">A KeyParams class</param>

<returns>A stream containing the KeyParams data</returns>
</member>
<member name="T:CEX.Cipher.Symmetric.Block.IBlockCipher" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="42">
<summary>
Block Cipher Interface
</summary> 
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="50">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="55">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.BlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="62">
<summary>
Get: Unit block size of internal cipher in bytes.
<para>Block size must be 16 or 32 bytes wide. 
Value set in class constructor.</para>
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="69">
<summary>
Get: The block ciphers type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.IsEncryption" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="74">
<summary>
Get: Initialized for encryption, false for decryption.
<para>Value set in <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/>.</para>
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.IsInitialized" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="80">
<summary>
Get: Cipher is ready to transform data
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.LegalKeySizes" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="85">
<summary>
Get: List of available legal key sizes
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.LegalRounds" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="90">
<summary>
Get: Available diffusion round assignments
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="95">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Rounds" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="100">
<summary>
Get: The number of diffusion rounds processed by the transform
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.DecryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="107">
<summary>
Decrypt a single block of bytes.
<para><see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
Input and Output arrays must be at least <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.BlockSize"/> in length.</para>
</summary>

<param name="Input">Encrypted bytes</param>
<param name="Output">Decrypted bytes</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.DecryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="117">
<summary>
Decrypt a block of bytes with offset parameters.
<para><see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
Input and Output arrays with Offsets must be at least <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.BlockSize"/> in length.</para>
</summary>

<param name="Input">Encrypted bytes</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Decrypted bytes</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="129">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.EncryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="134">
<summary>
Encrypt a block of bytes.
<para><see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
Input and Output array lengths must be at least <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.BlockSize"/> in length.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.EncryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="144">
<summary>
Encrypt a block of bytes with offset parameters.
<para><see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
Input and Output arrays with Offsets must be at least <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.BlockSize"/> in length.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="156">
<summary>
Initialize the Cipher
</summary>

<param name="Encryption">Using Encryption or Decryption mode</param>
<param name="KeyParam">Cipher key container. <para>The <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.LegalKeySizes"/> property contains valid sizes.</para></param>

<exception cref="T:CEX.Exception.CryptoSymmetricCipherException">Thrown if a null or invalid key is used</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="166">
<summary>
Transform a block of bytes.
<para><see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.
Input and Output array lengths must be at least <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.BlockSize"/> in length.</para>
</summary>

<param name="Input">Input bytes to Transform or Decrypt</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iblockcipher.h" line="176">
<summary>
Transform a block of bytes with offset parameters.
<para><see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.
Input and Output arrays with Offsets must be at least <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.BlockSize"/> in length.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="T:CEX.Seed.ISeed" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="13">
<summary>
ISeed: Pseudo random seed generator interface
</summary>
</member>
<member name="M:CEX.Seed.ISeed.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="21">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="26">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="33">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="38">
<summary>
Get: Algorithm name
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="45">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.ISeed.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="50">
<summary>
Get the pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Seed.ISeed.GetBytes(System.Int32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="57">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.ISeed.Next" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="66">
<summary>
Returns the next pseudo random 32bit integer
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Reset" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iseed.h" line="71">
<summary>
Reset the internal state
</summary>
</member>
<member name="T:CEX.Exception.CryptoGeneratorException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptogeneratorexception.h" line="8">
<summary>
Wraps exceptions thrown within Random Generator operations
</summary>
</member>
<member name="M:CEX.Exception.CryptoGeneratorException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptogeneratorexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoGeneratorException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptogeneratorexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoGeneratorException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptogeneratorexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:CTRDrbg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="12">
<summary>
An implementation of a Encryption Counter based DRBG
</summary>
</member>
<member name="F:DGCDrbg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="16">
<summary>
An implementation of a Digest Counter based DRBG
</summary>
</member>
<member name="F:HKDF" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="20">
<summary>
A Hash based Key Derivation Function HKDF
</summary>
</member>
<member name="F:KDF2Drbg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="24">
<summary>
An implementation of a Hash based Key Derivation Function PBKDF2
</summary>
</member>
<member name="F:PBKDF2" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="28">
<summary>
An implementation of a Hash based Key Derivation PKCS#5 Version 2
</summary>
</member>
<member name="F:SP20Drbg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="32">
<summary>
An implementation of a Salsa20 Counter based DRBG
</summary>
</member>
<member name="T:CEX.Enumeration.Generators" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\generators.h" line="7">
<summary>
Random Generators
</summary>
</member>
<member name="T:CEX.Generator.IGenerator" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="13">
<summary>
Pseudo random Generator Interface
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="21">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="26">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="34">
<summary>
Get: The generators type name
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.IsInitialized" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="39">
<summary>
Get: Generator is ready to produce data
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.KeySize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="44">
<summary>
<para>Minimum initialization key size in bytes; 
combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="50">
<summary>
Algorithm name
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="57">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Generate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="62">
<summary>
Generate a block of pseudo random bytes
</summary>

<param name="Output">Output array filled with random bytes</param>

<returns>Number of bytes generated</returns>
</member>
<member name="M:CEX.Generator.IGenerator.Generate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="71">
<summary>
Generate pseudo random bytes
</summary>

<param name="Output">Output array filled with random bytes</param>
<param name="OutOffset">The starting position within Output array</param>
<param name="Size">Number of bytes to generate</param>

<returns>Number of bytes generated</returns>
</member>
<member name="M:CEX.Generator.IGenerator.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="82">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
</member>
<member name="M:CEX.Generator.IGenerator.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="89">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
<param name="Ikm">Key material</param>
</member>
<member name="M:CEX.Generator.IGenerator.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="97">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
<param name="Ikm">Key material</param>
<param name="Nonce">Nonce value</param>
</member>
<member name="M:CEX.Generator.IGenerator.Update(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\igenerator.h" line="106">
<summary>
Update the Seed material
</summary>

<param name="Seed">Pseudo random seed material</param>
</member>
<member name="T:CEX.Generator.CTRDrbg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="39">
<summary>
CTRDrbg: An implementation of a Encryption Counter based Deterministic Random Byte Generator.
<para>A Block Cipher Counter DRBG as outlined in NIST document: SP800-90A</para>
</summary> 

<example>
<description>Generate an array of pseudo random bytes:</description>
<code>
CTRDrbg rnd(new RDX());
// initialize
rnd.Initialize(Salt, [Ikm], [Nonce]);
// generate bytes
rnd.Generate(Output, [Offset], [Size]);
</code>
</example>

<revisionHistory>
<revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
</revisionHistory>

<seealso cref="N:CEX.Cipher.Symmetric.Block">CEX::Cipher::Symmetric::Block Namespace</seealso>
<seealso cref="T:CEX.Enumeration.BlockCiphers">CEX::Enumeration::BlockCiphers Enumeration</seealso>

<remarks>
<description><h4>Implementation Notes:</h4></description>
<list type="bullet">
<item><description>Can be initialized with any block <see cref="T:CEX.Enumeration.BlockCiphers">cipher</see>.</description></item>
<item><description>Parallelized by default on a multi processer system when an input byte array of <see cref="M:CEX.Generator.CTRDrbg.ParallelMinimumSize"/> bytes or larger is used.</description></item>
<item><description>Parallelization can be disabled using the <see cref="M:CEX.Generator.CTRDrbg.IsParallel"/> property.</description></item>
<item><description>Combination of [Salt, Ikm, Nonce] must be: cipher key size +  cipher block size in length.</description></item>
<item><description>Nonce and Ikm are optional, (but recommended).</description></item>
</list>

<description><h4>Guiding Publications:</h4></description>
<list type="number">
<item><description>NIST SP800-90B: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">Recommendation for the Entropy Sources Used for Random Bit Generation</see>.</description></item>
<item><description>NIST Fips 140-2: <see href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Security Requirments For Cryptographic Modules</see>.</description></item>
<item><description>NIST SP800-22 1a: <see href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications</see>.</description></item>
<item><description>Security Bounds for the NIST Codebook-based: <see href="http://eprint.iacr.org/2006/379.pdf">Deterministic Random Bit Generator</see>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Generator.CTRDrbg.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="103">
<summary>
Get: The generators type name
</summary>
</member>
<member name="M:CEX.Generator.CTRDrbg.IsInitialized" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="108">
<summary>
Get: Generator is ready to produce data
</summary>
</member>
<member name="M:CEX.Generator.CTRDrbg.IsParallel" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="113">
<summary>
Get/Set: Automatic processor parallelization
</summary>
</member>
<member name="M:CEX.Generator.CTRDrbg.IV" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="118">
<summary>
Get: The current state of the initialization Vector
</summary>
</member>
<member name="M:CEX.Generator.CTRDrbg.KeySize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="123">
<summary>
<para>Minimum initialization key size in bytes; 
combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
</summary>
</member>
<member name="M:CEX.Generator.CTRDrbg.ParallelBlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="129">
<summary>
Get/Set: Parallel block size. Must be a multiple of <see cref="M:CEX.Generator.CTRDrbg.ParallelMinimumSize"/>.
</summary>
</member>
<member name="M:CEX.Generator.CTRDrbg.ParallelMaximumSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="134">
<summary>
Get: Maximum input size with parallel processing
</summary>
</member>
<member name="M:CEX.Generator.CTRDrbg.ParallelMinimumSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="139">
<summary>
Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
</summary>
</member>
<member name="M:CEX.Generator.CTRDrbg.ProcessorCount" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="144">
<remarks>
Get: Processor count
</remarks>
</member>
<member name="M:CEX.Generator.CTRDrbg.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="149">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Generator.CTRDrbg.#ctor(CEX.Cipher.Symmetric.Block.IBlockCipher*,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="156">
<summary>
Creates a HKDF Bytes Generator using the given HMAC function
</summary>

<param name="Hmac">The HMAC digest used</param>
<param name="KeySize">The internal ciphers key size; calculated automatically if this value is zero</param>

<exception cref="T:CEX.Exception.CryptoGeneratorException">Thrown if a null cipher is used</exception>
</member>
<member name="M:CEX.Generator.CTRDrbg.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="195">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Generator.CTRDrbg.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="205">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Generator.CTRDrbg.Generate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="210">
<summary>
Generate a block of pseudo random bytes
</summary>

<param name="Output">Output array filled with random bytes</param>

<returns>Number of bytes generated</returns>
</member>
<member name="M:CEX.Generator.CTRDrbg.Generate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="219">
<summary>
Generate pseudo random bytes
</summary>

<param name="Output">Output array filled with random bytes</param>
<param name="OutOffset">Position within Output array</param>
<param name="Size">Number of bytes to generate</param>

<returns>Number of bytes generated</returns>

<exception cref="T:CEX.Exception.CryptoGeneratorException">Thrown if the output buffer is too small</exception>
</member>
<member name="M:CEX.Generator.CTRDrbg.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="232">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value; size must be at least cipher key size + cipher block size</param>

<exception cref="T:CEX.Exception.CryptoGeneratorException">Thrown if the Salt is too small</exception>
</member>
<member name="M:CEX.Generator.CTRDrbg.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="241">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
<param name="Ikm">Key material</param>
</member>
<member name="M:CEX.Generator.CTRDrbg.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="249">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
<param name="Ikm">Key material</param>
<param name="Nonce">Nonce value</param>
</member>
<member name="M:CEX.Generator.CTRDrbg.Update(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrdrbg.h" line="258">
<summary>
Update the Salt material
</summary>

<param name="Salt">Salt value; size must be at least cipher key size + cipher block size</param>

<exception cref="T:CEX.Exception.CryptoGeneratorException">Thrown if the Salt is too small</exception>
</member>
<member name="T:CEX.Prng.CTRPrng" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="45">
<summary>
CTRPrng: An implementation of a Encryption Counter based Deterministic Random Number Generator.
<para>A Block Cipher Counter DRBG as outlined in NIST document: SP800-90A</para>
</summary> 

<example>
<description>Example of generating a pseudo random integer:</description>
<code>
CTRPrng rnd([BlockCiphers], [SeedGenerators]);
// get random int
int num = rnd.Next([Minimum], [Maximum]);
</code>
</example>

<revisionHistory>
<revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
</revisionHistory>

<seealso cref="N:CEX.Cipher.Symmetric.Block">CEX::Cipher::Symmetric::Block Namespace</seealso>
<seealso cref="N:CEX.Seed">CEX::Seed ISeed Interface</seealso>
<seealso cref="T:CEX.Enumeration.BlockCiphers">CEX::Enumeration::BlockCiphers Enumeration</seealso>

<remarks>
<description><h4>Implementation Notes:</h4></description>
<list type="bullet">
<item><description>Can be initialized with any block <see cref="T:CEX.Enumeration.BlockCiphers">cipher</see>.</description></item>
<item><description>Can use either a random seed generator for initialization, or a user supplied Seed array.</description></item>
<item><description>Numbers generated with the same seed will produce the same random output.</description></item>
</list>

<description><h4>Guiding Publications:</h4></description>
<list type="number">
<item><description>NIST SP800-90B: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">Recommendation for the Entropy Sources Used for Random Bit Generation</see>.</description></item>
<item><description>NIST Fips 140-2: <see href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Security Requirments For Cryptographic Modules</see>.</description></item>
<item><description>NIST SP800-22 1a: <see href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications</see>.</description></item>
<item><description>Security Bounds for the NIST Codebook-based: <see href="http://eprint.iacr.org/2006/379.pdf">Deterministic Random Bit Generator</see>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Prng.CTRPrng.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="104">
<summary>
Get: The prngs type name
</summary>
</member>
<member name="M:CEX.Prng.CTRPrng.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="109">
<summary>
Get: Digest name
</summary>
</member>
<member name="M:CEX.Prng.CTRPrng.#ctor(&lt;unknown type&gt;,&lt;unknown type&gt;,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="116">
<summary>
Initialize this class
</summary>

<param name="BlockEngine">The block cipher that powers the rng (default is RDX)</param>
<param name="SeedEngine">The Seed engine used to create keyng material (default is CSPRsg)</param>
<param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
<param name="KeySize">The key size (in bytes) of the symmetric cipher; a <c>0</c> value will auto size the key</param>

<exception cref="T:CEX.Exception.CryptoRandomException">Thrown if the buffer size is too small (min. 64)</exception>
</member>
<member name="M:CEX.Prng.CTRPrng.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,&lt;unknown type&gt;,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="146">
<summary>
Initialize the class with a Seed; note: the same seed will produce the same random output
</summary>

<param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is key size + counter 16)</param>
<param name="BlockEngine">The block cipher that powers the rng (default is RDX)</param>
<param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>

<exception cref="T:CEX.Exception.CryptoRandomException">Thrown if the seed is null or too small</exception>
</member>
<member name="M:CEX.Prng.CTRPrng.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="176">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Prng.CTRPrng.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="186">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Prng.CTRPrng.GetBytes(System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="191">
<summary>
Return an array filled with pseudo random bytes
</summary>

<param name="Size">Size of requested byte array</param>

<returns>Random byte array</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="200">
<summary>
Fill an array with pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Prng.CTRPrng.Next" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="207">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<returns>Random 32bit integer</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.Next(System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="214">
<summary>
Get an pseudo random unsigned 32bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random 32bit integer</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.Next(System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="223">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random 32bit integer</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.NextLong" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="233">
<summary>
Get a pseudo random unsigned 64bit integer
</summary>

<returns>Random 64bit integer</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.NextLong(System.UInt64)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="240">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random 64bit integer</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.NextLong(System.UInt64,System.UInt64)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="249">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random 64bit integer</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.Reset" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.h" line="259">
<summary>
Reset the generator instance
</summary>
</member>
<member name="T:CEX.Seed.CSPRsg" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="17">
<summary>
CSPRsg: Operating system pseudo random provider.
<para>On a windows system uses the CryptGenRandom api, otherwise uses calls to arc4random.</para>
</summary>

<example>
<description>Example of getting a seed value:</description>
<code>
CSPRsg gen;
gen.GetSeed(Output);
</code>
</example>

<revisionHistory>
<revision date="2015/06/09" version="1.0.0.0">Initial release</revision>
</revisionHistory>
</member>
<member name="M:CEX.Seed.CSPRsg.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="43">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="48">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="55">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="63">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="73">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="78">
<summary>
Fill the buffer with random bytes
</summary>

<param name="Input">The array to fill</param>
</member>
<member name="M:CEX.Seed.CSPRsg.GetBytes(System.Int32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="85">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.CSPRsg.Next" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="94">
<summary>
Returns the next pseudo random 32bit integer
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Reset" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\csprsg.h" line="99">
<summary>
Reset the internal state
</summary>
</member>
<member name="T:CEX.Exception.CryptoException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoexception.h" line="8">
<summary>
Generalized cryptographic error container
</summary>
</member>
<member name="M:CEX.Exception.CryptoException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptoexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="T:CEX.Helper.BlockCipherFromName" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\blockcipherfromname.h" line="17">
<summary>
BlockCipherFromName: Get a Block Cipher instance from it's enumeration name.
</summary>
</member>
<member name="M:CEX.Helper.BlockCipherFromName.GetInstance(&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\blockcipherfromname.h" line="23">
<summary>
Get a block cipher instance with default initialization parameters
</summary>

<param name="EngineType">The block cipher enumeration name</param>

<returns>An initialized block cipher</returns>

<exception cref="T:CEX.Exception.CryptoException">Thrown if the enumeration name is not supported</exception>
</member>
<member name="M:CEX.Helper.BlockCipherFromName.GetInstance(&lt;unknown type&gt;,System.Int32,System.Int32,&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\blockcipherfromname.h" line="34">
<summary>
Get a block cipher instance with specified initialization parameters
</summary>

<param name="EngineType">The block cipher enumeration name</param>
<param name="BlockSize">The cipher block size</param>
<param name="RoundCount">The number of cipher rounds</param>
<param name="KdfEngine">The ciphers key expansion engine (HX ciphers)</param>

<returns>An initialized block cipher</returns>

<exception cref="T:CEX.Exception.CryptoException">Thrown if the enumeration name is not supported</exception>
</member>
<member name="M:CEX.Prng.CTRPrng.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.cpp" line="12">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Prng.CTRPrng.GetBytes(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.cpp" line="48">
<summary>
Return an array filled with pseudo random bytes
</summary>

<param name="Size">Size of requested byte array</param>

<returns>Random byte array</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.cpp" line="62">
<summary>
Fill an array with pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Prng.CTRPrng.Next" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.cpp" line="107">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.Next(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.cpp" line="117">
<summary>
Get an pseudo random unsigned 32bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.Next(System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.cpp" line="139">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.NextLong" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.cpp" line="154">
<summary>
Get a pseudo random unsigned 64bit integer
</summary>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.NextLong(System.UInt64)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.cpp" line="164">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.NextLong(System.UInt64,System.UInt64)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.cpp" line="186">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.CTRPrng.Reset" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ctrprng.cpp" line="201">
<summary>
Reset the generator instance
</summary>
</member>
</members>
</doc>