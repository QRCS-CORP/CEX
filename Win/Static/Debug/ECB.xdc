<?xml version="1.0"?><doc>
<members>
<member name="F:ECB" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ciphermodes.h" line="12">
<summary>
Electronic CodeBook Mode (not secure, testing only)
</summary>
</member>
<member name="F:CBC" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ciphermodes.h" line="16">
<summary>
Cipher Block Chaining Mode
</summary>
</member>
<member name="F:CFB" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ciphermodes.h" line="20">
<summary>
Cipher FeedBack Mode
</summary>
</member>
<member name="F:CTR" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ciphermodes.h" line="24">
<summary>
SIC Counter Mode
</summary>
</member>
<member name="F:OFB" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ciphermodes.h" line="28">
<summary>
Output FeedBack Mode
</summary>
</member>
<member name="T:CEX.Enumeration.CipherModes" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ciphermodes.h" line="7">
<summary>
Cipher Modes
</summary>
</member>
<member name="T:CEX.Exception.CryptoCipherModeException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptociphermodeexception.h" line="8">
<summary>
Wraps exceptions thrown within Symmetric cipher mode operations
</summary>
</member>
<member name="M:CEX.Exception.CryptoCipherModeException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptociphermodeexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoCipherModeException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptociphermodeexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoCipherModeException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptociphermodeexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
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
<member name="T:CEX.Cipher.Symmetric.Block.Mode.ICipherMode" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="39">
<summary>
Cipher Mode Interface
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="47">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="52">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.BlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="59">
<summary>
Get: Unit block size of internal cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Engine" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="64">
<summary>
Get: Underlying Cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="69">
<summary>
Get: The cipher modes type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.IsEncryption" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="74">
<summary>
Get: Initialized for encryption, false for decryption
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.IsInitialized" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="79">
<summary>
Get: Cipher is ready to transform data
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.IsParallel" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="84">
<summary>
Get/Set: Automatic processor parallelization
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.IV" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="89">
<summary>
Get: The current state of the initialization Vector
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.LegalKeySizes" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="94">
<summary>
Get: List of available legal key sizes
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="99">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ParallelBlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="104">
<summary>
Get/Set: Parallel block size. Must be a multiple of <see cref="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ParallelMinimumSize"/>.
</summary>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, or  block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ParallelMaximumSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="111">
<summary>
Get: Maximum input size with parallel processing
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ParallelMinimumSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="116">
<summary>
Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ProcessorCount" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="121">
<remarks>
Get: Processor count
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="128">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="133">
<summary>
Initialize the Cipher
</summary>

<param name="Encryption">Cipher is used. for encryption, false to decrypt</param>
<param name="KeyParam">The KeyParams containing key and vector</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="141">
<summary>
<para>Transform a block of bytes. Parallel capable function if Output array length is at least equal to <see cref="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ParallelMinimumSize"/>.
Initialize() must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\iciphermode.h" line="150">
<summary>
<para>Transform a block of bytes with offset parameters.  Parallel capable function if Output array length is at least equal to <see cref="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ParallelMinimumSize"/>.
Initialize() must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="T:CEX.Cipher.Symmetric.Block.Mode.ECB" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="36">
<summary>
Implements an Electronic Cookbook Mode: ECB (Insecure Mode; For Testing Only!).
<para>ECB as outlined in the NIST document: SP800-38A</para>
</summary> 

<example>
<description>Example using an <c>ICipherMode</c> interface:</description>
<code>
ECB cipher(new RDX());
// initialize for encryption
cipher.Initialize(true, KeyParams(Key));
// encrypt a block
cipher.Transform(Input, Output);
</code>
</example>

<revisionHistory>
<revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
</revisionHistory>

<seealso cref="N:CEX.Cipher.Symmetric.Block">CEX::Cipher::Symmetric::Block Namespace</seealso>
<seealso cref="T:CEX.Cipher.Symmetric.Block.Mode.ICipherMode">CEX::Cipher::Symmetric::Block::Mode ICipherMode Interface</seealso>
<seealso cref="T:CEX.Enumeration.BlockCiphers">CEX::Enumeration BlockCiphers Enumeration</seealso>

<remarks>
<description><h4>Implementation Notes:</h4></description>
<list type="bullet">
<item><description>ECB is not a secure mode, and should only be used for testing.</description></item>
</list>

<description><h4>Guiding Publications:</h4></description>
<list type="number">
<item><description>NIST: <see href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</see>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.BlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="87">
<summary>
Get: Unit block size of internal cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Engine" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="92">
<summary>
Get: Underlying Cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="97">
<summary>
Get: The cipher modes type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.IsEncryption" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="102">
<summary>
Get: Initialized for encryption, false for decryption
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.IsInitialized" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="107">
<summary>
Get: Cipher is ready to transform data
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.IsParallel" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="112">
<summary>
Get/Set: Automatic processor parallelization
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.IV" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="117">
<summary>
Get: The current state of the initialization Vector
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.LegalKeySizes" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="122">
<summary>
Get: Available Encryption Key Sizes in bytes
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="127">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.ParallelBlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="132">
<summary>
Get/Set: Parallel block size. Must be a multiple of <see cref="M:CEX.Cipher.Symmetric.Block.Mode.ECB.ParallelMinimumSize"/>.
</summary>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, or  block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.ParallelMaximumSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="139">
<summary>
Get: Maximum input size with parallel processing
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.ParallelMinimumSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="144">
<summary>
Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.ProcessorCount" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="149">
<remarks>
Get: Processor count
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.#ctor(CEX.Cipher.Symmetric.Block.IBlockCipher*)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="156">
<summary>
Initialize the Cipher
</summary>

<param name="Cipher">Underlying encryption algorithm</param>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a null Cipher or valid block size is used</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="180">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.DecryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="190">
<summary>
<para>Decrypt a single block of bytes.
<see cref="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Encrypted bytes</param>
<param name="Output">Decrypted bytes</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.DecryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="199">
<summary>
<para>Decrypt a block of bytes with offset parameters.
<see cref="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Encrypted bytes</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Decrypted bytes</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="210">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.EncryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="215">
<summary>
<para>Encrypt a block of bytes. 
<see cref="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.EncryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="224">
<summary>
<para>Encrypt a block of bytes with offset parameters. 
<see cref="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="235">
<summary>
Initialize the Cipher
</summary>

<param name="Encryption">Cipher is used. for encryption, false to decrypt</param>
<param name="KeyParam">KeyParam containing key and vector</param>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a null Key or IV is used</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="245">
<summary>
<para>Transform a block of bytes. 
<see cref="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>
<param name="Input">Input bytes to Transform</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\ecb.h" line="253">
<summary>
<para>Transform a block of bytes with offset parameters. 
<see cref="M:CEX.Cipher.Symmetric.Block.Mode.ECB.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="T:CEX.Utility.ParallelUtils" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\parallelutils.h" line="17">
<summary>
Parallel functions class
</summary> 
</member>
</members>
</doc>