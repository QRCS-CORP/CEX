<?xml version="1.0"?><doc>
<members>
<member name="T:CEX.Exception.CryptoException" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoexception.h" line="8">
<summary>
Generalized cryptographic error container
</summary>
</member>
<member name="M:CEX.Exception.CryptoException.Message" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoexception.h" line="18">
<summary>
Get/Set: The message associated with the error
</summary>
</member>
<member name="M:CEX.Exception.CryptoException.Origin" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoexception.h" line="23">
<summary>
Get/Set: The origin of the exception in the format Class
</summary>
</member>
<member name="M:CEX.Exception.CryptoException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoexception.h" line="29">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoexception.h" line="40">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="T:CEX.Exception.CryptoCipherModeException" decl="false" source="c:\users\john\documents\github\cex\engine\cryptociphermodeexception.h" line="8">
<summary>
Wraps exceptions thrown within Symmetric cipher mode operations
</summary>
</member>
<member name="M:CEX.Exception.CryptoCipherModeException.Message" decl="false" source="c:\users\john\documents\github\cex\engine\cryptociphermodeexception.h" line="18">
<summary>
Get/Set: The message associated with the error
</summary>
</member>
<member name="M:CEX.Exception.CryptoCipherModeException.Origin" decl="false" source="c:\users\john\documents\github\cex\engine\cryptociphermodeexception.h" line="23">
<summary>
Get/Set: The origin of the exception in the format Class
</summary>
</member>
<member name="M:CEX.Exception.CryptoCipherModeException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptociphermodeexception.h" line="28">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoCipherModeException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptociphermodeexception.h" line="39">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:ECB" decl="false" source="c:\users\john\documents\github\cex\engine\ciphermodes.h" line="12">
<summary>
Electronic CodeBook Mode (not secure, testing only)
</summary>
</member>
<member name="F:CBC" decl="false" source="c:\users\john\documents\github\cex\engine\ciphermodes.h" line="16">
<summary>
Cipher Block Chaining Mode
</summary>
</member>
<member name="F:CFB" decl="false" source="c:\users\john\documents\github\cex\engine\ciphermodes.h" line="20">
<summary>
Cipher FeedBack Mode
</summary>
</member>
<member name="F:CTR" decl="false" source="c:\users\john\documents\github\cex\engine\ciphermodes.h" line="24">
<summary>
SIC Counter Mode
</summary>
</member>
<member name="F:OFB" decl="false" source="c:\users\john\documents\github\cex\engine\ciphermodes.h" line="28">
<summary>
Output FeedBack Mode
</summary>
</member>
<member name="T:CEX.Enumeration.CipherModes" decl="false" source="c:\users\john\documents\github\cex\engine\ciphermodes.h" line="7">
<summary>
Cipher Modes
</summary>
</member>
<member name="F:RHX" decl="false" source="c:\users\john\documents\github\cex\engine\blockciphers.h" line="12">
<summary>
An implementation based on the Rijndael Block Cipher, using HKDF with a SHA512 HMAC for expanded key generation
</summary>
</member>
<member name="F:SHX" decl="false" source="c:\users\john\documents\github\cex\engine\blockciphers.h" line="16">
<summary>
The Serpent Block Cipher Extended with an HKDF Key Schedule
</summary>
</member>
<member name="F:THX" decl="false" source="c:\users\john\documents\github\cex\engine\blockciphers.h" line="20">
<summary>
A Twofish Block Cipher Extended with an HKDF Key Schedule
</summary>
</member>
<member name="T:CEX.Enumeration.BlockCiphers" decl="false" source="c:\users\john\documents\github\cex\engine\blockciphers.h" line="7">
<summary>
Block Ciphers
</summary>
</member>
<member name="T:CEX.Exception.CryptoSymmetricCipherException" decl="false" source="c:\users\john\documents\github\cex\engine\cryptosymmetriccipherexception.h" line="8">
<summary>
Wraps exceptions thrown within a Symmetric cipher operational context
</summary>
</member>
<member name="M:CEX.Exception.CryptoSymmetricCipherException.Message" decl="false" source="c:\users\john\documents\github\cex\engine\cryptosymmetriccipherexception.h" line="18">
<summary>
Get/Set: The message associated with the error
</summary>
</member>
<member name="M:CEX.Exception.CryptoSymmetricCipherException.Origin" decl="false" source="c:\users\john\documents\github\cex\engine\cryptosymmetriccipherexception.h" line="23">
<summary>
Get/Set: The origin of the exception in the format Class
</summary>
</member>
<member name="M:CEX.Exception.CryptoSymmetricCipherException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptosymmetriccipherexception.h" line="29">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoSymmetricCipherException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptosymmetriccipherexception.h" line="40">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="T:CEX.Exception.CryptoDigestException" decl="false" source="c:\users\john\documents\github\cex\engine\cryptodigestexception.h" line="8">
<summary>
Cryptographic digest error container
</summary>
</member>
<member name="M:CEX.Exception.CryptoDigestException.Message" decl="false" source="c:\users\john\documents\github\cex\engine\cryptodigestexception.h" line="18">
<summary>
Get/Set: The message associated with the error
</summary>
</member>
<member name="M:CEX.Exception.CryptoDigestException.Origin" decl="false" source="c:\users\john\documents\github\cex\engine\cryptodigestexception.h" line="23">
<summary>
Get/Set: The origin of the exception in the format Class
</summary>
</member>
<member name="M:CEX.Exception.CryptoDigestException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptodigestexception.h" line="29">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoDigestException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptodigestexception.h" line="40">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:Blake256" decl="false" source="c:\users\john\documents\github\cex\engine\digests.h" line="12">
<summary>
The Blake digest with a 256 bit return size
</summary>
</member>
<member name="F:Blake512" decl="false" source="c:\users\john\documents\github\cex\engine\digests.h" line="16">
<summary>
The Blake digest with a 512 bit return size
</summary>
</member>
<member name="F:Keccak256" decl="false" source="c:\users\john\documents\github\cex\engine\digests.h" line="20">
<summary>
The SHA-3 digest based on Keccak with a 256 bit return size
</summary>
</member>
<member name="F:Keccak512" decl="false" source="c:\users\john\documents\github\cex\engine\digests.h" line="24">
<summary>
The SHA-3 digest based on Keccak with a 512 bit return size
</summary>
</member>
<member name="F:SHA256" decl="false" source="c:\users\john\documents\github\cex\engine\digests.h" line="28">
<summary>
The SHA-2 digest with a 256 bit return size
</summary>
</member>
<member name="F:SHA512" decl="false" source="c:\users\john\documents\github\cex\engine\digests.h" line="32">
<summary>
The SHA-2 digest with a 512 bit return size
</summary>
</member>
<member name="F:Skein256" decl="false" source="c:\users\john\documents\github\cex\engine\digests.h" line="36">
<summary>
The Skein digest with a 256 bit return size
</summary>
</member>
<member name="F:Skein512" decl="false" source="c:\users\john\documents\github\cex\engine\digests.h" line="40">
<summary>
The Skein digest with a 512 bit return size
</summary>
</member>
<member name="F:Skein1024" decl="false" source="c:\users\john\documents\github\cex\engine\digests.h" line="44">
<summary>
The Skein digest with a 1024 bit return size
</summary>
</member>
<member name="T:CEX.Enumeration.Digests" decl="false" source="c:\users\john\documents\github\cex\engine\digests.h" line="7">
<summary>
Message Digests
</summary>
</member>
<member name="T:CEX.Digest.IDigest" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="12">
<summary>
Hash Digest Interface
</summary>
</member>
<member name="M:CEX.Digest.IDigest.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="20">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Digest.IDigest.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="25">
<summary>
Finalizer
</summary>
</member>
<member name="M:CEX.Digest.IDigest.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="32">
<summary>
Get: The Digests internal block size in bytes
</summary>
</member>
<member name="M:CEX.Digest.IDigest.DigestSize" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="37">
<summary>
Get: Size of returned hash value in bytes
</summary>
</member>
<member name="M:CEX.Digest.IDigest.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="42">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.IDigest.Name" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="47">
<summary>
Get: The Digest name
</summary>
</member>
<member name="M:CEX.Digest.IDigest.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="54">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>
</member>
<member name="M:CEX.Digest.IDigest.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="63">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.IDigest.Destroy" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="71">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.IDigest.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="76">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>
</member>
<member name="M:CEX.Digest.IDigest.Reset" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="86">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.IDigest.Update(System.Byte)" decl="false" source="c:\users\john\documents\github\cex\engine\idigest.h" line="91">
<summary>
Update the message digest with a single byte
</summary>

<param name="Input">Input byte</param>
</member>
<member name="T:CEX.Utility.IntUtils" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="13">
<summary>
Integer functions class
</summary>
</member>
<member name="M:CEX.Utility.IntUtils.BitPrecision(System.UInt64)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="20">
<summary>
Get a byte value from a 32 bit integer
</summary>

<param name="Value">The integer value</param>
<param name="Shift">The number of bytes to shift</param>

<returns>Bit precision</returns>
<summary>
Get the bit precision value
</summary>

<param name="Value">initial value</param>

<returns>Bit precision</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BitReverse(System.Byte)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="45">
<summary>
Reverse a byte
</summary>

<param name="Value">Initial value</param>

<returns>The revered byte</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BitReverse(System.UInt16)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="59">
<summary>
Reverse an unsigned 16 bit integer
</summary>

<param name="Value">Initial value</param>

<returns>The reversed ushort</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BitReverse(System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="74">
<summary>
Reverse an unsigned 32 bit integer
</summary>

<param name="Value">Initial value</param>

<returns>The reversed uint</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BitReverse(System.UInt64)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="90">
<summary>
Reverse an unsigned 64 bit integer
</summary>

<param name="Value">Initial value</param>

<returns>The reversed ulong</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytePrecision(System.UInt64)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="112">
<summary>
Get the byte precision
</summary>

<param name="Value">The sample value</param>

<returns>The byte precision</returns>
</member>
<member name="M:CEX.Utility.IntUtils.ByteReverse(System.UInt16)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="121">
<summary>
Reverse a 16 bit integer
</summary>

<param name="Value">The initial value</param>

<returns>The reversed ushort</returns>
</member>
<member name="M:CEX.Utility.IntUtils.ByteReverse(System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="133">
<summary>
Reverse a 32 bit integer
</summary>

<param name="Value">The initial value</param>

<returns>The reversed uint</returns>
</member>
<member name="M:CEX.Utility.IntUtils.ByteReverse(System.UInt64)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="155">
<summary>
Reverse a 64 bit integer
</summary>

<param name="Value">The initial value</param>

<returns>The reversed ulong</returns>
</member>
<member name="M:CEX.Utility.IntUtils.Be16ToBytes(System.UInt16!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="185">
<summary>
Convert a Big Endian 16 bit word to bytes
</summary>

<param name="Value">The 16 bit word</param>
<param name="Output">The destination bytes</param>
<param name="OutOffset">OutOffset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.Be32ToBytes(System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="198">
<summary>
Convert a Big Endian 32 bit word to bytes
</summary>

<param name="Value">The 32 bit word</param>
<param name="Output">The destination bytes</param>
<param name="OutOffset">OutOffset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.Be64ToBytes(System.UInt64!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="213">
<summary>
Convert a Big Endian 64 bit dword to bytes
</summary>

<param name="Value">The 64 bit word</param>
<param name="Output">The destination bytes</param>
<param name="OutOffset">OutOffset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToBe16(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="232">
<summary>
Convert a byte array to a Big Endian 16 bit word
</summary>

<param name="Input">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 16 bit word in Big Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToBe32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="246">
<summary>
Convert a byte array to a Big Endian 32 bit word
</summary>

<param name="Input">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 32 bit word in Big Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToBe64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="262">
<summary>
Convert a byte array to a Big Endian 64 bit dword
</summary>

<param name="Input">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 64 bit word in Big Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.Le16ToBytes(System.UInt16!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="284">
<summary>
Convert a Little Endian 16 bit word to bytes
</summary>

<param name="Value">The 16 bit word</param>
<param name="Output">The destination bytes</param>
<param name="OutOffset">OutOffset within the destination block</param>
</member>
<member name="M:CEX.Utility.IntUtils.Le32ToBytes(System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="297">
<summary>
Convert a Little Endian 32 bit word to bytes
</summary>

<param name="Value">The 32 bit word</param>
<param name="Output">The destination bytes</param>
<param name="OutOffset">OutOffset within the destination block</param>
</member>
<member name="M:CEX.Utility.IntUtils.Le64ToBytes(System.UInt64!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="312">
<summary>
Convert a Little Endian 64 bit dword to bytes
</summary>

<param name="DWord">The 64 bit word</param>
<param name="Output">The destination bytes</param>
<param name="OutOffset">OutOffset within the destination block</param>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToLe16(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="331">
<summary>
Convert a byte array to a Little Endian 16 bit word
</summary>

<param name="Input">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 16 bit word in Little Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToLe32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="345">
<summary>
Convert a byte array to a Little Endian 32 bit word
</summary>

<param name="Input">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 32 bit word in Little Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToLe64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="361">
<summary>
Convert a byte array to a Little Endian 64 bit dword
</summary>

<param name="Input">The source byte array</param>
<param name="InOffset">Offset within the source array</param>
<returns>A 64 bit word in Little Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToWord16(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="382">
<summary>
Convert a byte array to a system aligned 16 bit word
</summary>

<param name="Input">The source byte array</param>

<returns>A 16 bit word in native Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToWord16(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="396">
<summary>
Convert a byte array to a system aligned 16 bit word
</summary>

<param name="Input">The source byte array</param>
<param name="InOffset">InOffset within the source array</param>

<returns>A 16 bit word in native Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToWord32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="411">
<summary>
Convert a byte array to a system aligned 32 bit word
</summary>

<param name="Input">The source byte array</param>

<returns>A 32 bit word in native Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToWord32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="427">
<summary>
Convert a byte array to a system aligned 32 bit word
</summary>

<param name="Input">The source byte array</param>
<param name="InOffset">InOffset within the source array</param>

<returns>A 32 bit word in native Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToWord64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="444">
<summary>
Convert a byte array to a system aligned 64 bit word
</summary>

<param name="Input">The source byte array</param>

<returns>A 64 bit word in native Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToWord64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="464">
<summary>
Convert a byte array to a system aligned 64 bit word
</summary>

<param name="Input">The source byte array</param>
<param name="InOffset">InOffset within the source array</param>

<returns>A 64 bit word in native Endian format</returns>
</member>
<member name="M:CEX.Utility.IntUtils.Word16ToBytes(System.UInt16!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="485">
<summary>
Convert a system aligned Endian 16 bit word to bytes
</summary>

<param name="Value">The 16 bit word</param>
<param name="Output">The destination bytes</param>
</member>
<member name="M:CEX.Utility.IntUtils.Word16ToBytes(System.UInt16!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="497">
<summary>
Convert a system aligned Endian 16 bit word to bytes
</summary>

<param name="Value">The 16 bit word</param>
<param name="Output">The destination bytes</param>
<param name="OutOffset">OutOffset within the destination block</param>
</member>
<member name="M:CEX.Utility.IntUtils.Word32ToBytes(System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="510">
<summary>
Convert a system aligned Endian 32 bit word to bytes
</summary>

<param name="Value">The 32 bit word</param>
<param name="Output">The destination bytes</param>
</member>
<member name="M:CEX.Utility.IntUtils.Word32ToBytes(System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="524">
<summary>
Convert a system aligned Endian 32 bit word to bytes
</summary>

<param name="Value">The 32 bit word</param>
<param name="Output">The destination bytes</param>
<param name="OutOffset">OutOffset within the destination block</param>
</member>
<member name="M:CEX.Utility.IntUtils.Word64ToBytes(System.UInt64!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="539">
<summary>
Convert a system aligned Endian 64 bit word to bytes
</summary>

<param name="Value">The 64 bit word</param>
<param name="Output">The destination bytes</param>
</member>
<member name="M:CEX.Utility.IntUtils.Word64ToBytes(System.UInt64!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="557">
<summary>
Convert a system aligned Endian 64 bit word to bytes
</summary>

<param name="Value">The 64 bit word</param>
<param name="Output">The destination bytes</param>
<param name="OutOffset">OutOffset within the destination block</param>
</member>
<member name="M:CEX.Utility.IntUtils.Crop(System.UInt64,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="803">
<summary>
Crop a 64 bit integer value
</summary>

<param name="Value">The initial value</param>
<param name="Size">The number of bits in the new integer</param>

<returns>The cropped integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.Min(System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="844">
<summary>
Return the smaller of two values
</summary>

<param name="A">The first comparison value</param>
<param name="B">The second comparison value</param>

<returns>The smaller value</returns>
</member>
<member name="M:CEX.Utility.IntUtils.Parity(System.UInt64)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="872">
<summary>
Get the parity bit from a 64 bit integer
</summary>

<param name="Value">The initial value</param>

<returns>The parity value</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotateLeft(System.UInt32,System.Int32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="886">
<summary>
Rotate shift an unsigned 32 bit integer to the left
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The left shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotateLeft(System.UInt64,System.Int32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="899">
<summary>
Rotate shift an unsigned 64 bit integer to the left
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The left shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotateRight(System.UInt32,System.Int32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="912">
<summary>
Rotate shift a 32 bit integer to the right
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The right shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotateRight(System.UInt64,System.Int32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="925">
<summary>
Rotate shift an unsigned 64 bit integer to the right
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The right shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotlFixed(System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="938">
<summary>
Rotate shift an unsigned 32 bit integer to the left
</summary>

<param name="Value">The initial value</param>
<param name="Y">The number of bits to shift</param>

<returns>The left shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotrFixed(System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="951">
<summary>
Rotate shift an unsigned 32 bit integer to the right
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The right shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotlFixed64(System.UInt64,System.Int32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="964">
<summary>
Rotate shift an unsigned 64 bit integer to the left
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The left shifted integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.RotrFixed64(System.UInt64,System.Int32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="977">
<summary>
Rotate shift an unsigned 64 bit integer to the right
</summary>

<param name="Value">The initial value</param>
<param name="Shift">The number of bits to shift</param>

<returns>The right shifted 64 bit integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.ToBit16(System.UInt16)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1202">
<summary>

</summary>

<param name="Value">The initial value</param>

<returns></returns>
</member>
<member name="M:CEX.Utility.IntUtils.ToBit32(System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1216">
<summary>

</summary>

<param name="Value">The initial value</param>

<returns></returns>
</member>
<member name="M:CEX.Utility.IntUtils.ToBit64(System.UInt64)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1230">
<summary>

</summary>

<param name="Value">The initial value</param>

<returns></returns>
</member>
<member name="M:CEX.Utility.IntUtils.ToInt16(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1259">
<summary>
Convert bytes to a Little Endian 16 bit word
</summary>

<param name="Input">The input bytes</param>

<returns>The 16 bit integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.ToInt32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1271">
<summary>
Convert bytes to a Little Endian 32 bit word
</summary>

<param name="Input">The input bytes</param>

<returns>The 32 bit integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.ToInt64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1283">
<summary>
Convert bytes to a Little Endian 64 bit word
</summary>

<param name="Input">The input bytes</param>

<returns>The 64 bit integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.ToInt16(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1295">
<summary>
Convert bytes to a Little Endian 16 bit word
</summary>

<param name="Input">The input bytes</param>
<param name="InOffset">The starting offset within the input array</param>

<returns>The 16 bit integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.ToInt32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1308">
<summary>
Convert bytes to a Little Endian 32 bit word
</summary>

<param name="Input">The input bytes</param>
<param name="InOffset">The starting offset within the input array</param>

<returns>The 32bit integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.ToInt64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1321">
<summary>
Convert bytes to a Little Endian 64 bit word
</summary>

<param name="Input">The input bytes</param>
<param name="InOffset">The starting offset within the input array</param>

<returns>The 64 bit integer</returns>
</member>
<member name="M:CEX.Utility.IntUtils.Word64sToBytes(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1349">
<summary>
Convert an array of 64 bit words into a byte array
</summary>

<param name="Input">The input integer array</param>
<param name="Output">The output byte array</param>
</member>
<member name="M:CEX.Utility.IntUtils.BytesToWord64s(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32,std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1362">
<summary>
Convert an array of 64 bit words into a byte array
</summary>

<param name="Input">The input integer array</param>
<param name="InOffset">The input arrays starting offset</param>
<param name="Length">The number of bytes to return</param>
<param name="Output">The input integer array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR32(System.Byte!System.Runtime.CompilerServices.IsConst**!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.Byte**!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1379">
<summary>
Block XOR 4 bytes
</summary>

<param name="Input">The source array</param>
<param name="Output">The destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1387">
<summary>
Block XOR 4 bytes
</summary>

<param name="Input">The source array</param>
<param name="Output">The destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR32(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1395">
<summary>
Block XOR 4 bytes
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1405">
<summary>
Block XOR 8 bytes
</summary>

<param name="Input">The source array</param>
<param name="Output">The destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR64(System.Byte!System.Runtime.CompilerServices.IsConst**!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.Byte**!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1413">
<summary>
Block XOR 8 bytes
</summary>

<param name="Input">The source array</param>
<param name="Output">The destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR64(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1421">
<summary>
Block XOR 8 bytes
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR128(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1431">
<summary>
Block XOR 16 bytes
</summary>

<param name="Input">The source array</param>
<param name="Output">The destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR128(System.Byte!System.Runtime.CompilerServices.IsConst**!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.Byte**!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1439">
<summary>
Block XOR 16 bytes
</summary>

<param name="Input">The source array</param>
<param name="Output">The destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR128(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1447">
<summary>
Block XOR 16 bytes
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR256(System.Byte!System.Runtime.CompilerServices.IsConst**!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.Byte**!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1457">
<summary>
Block XOR 32 bytes
</summary>

<param name="Input">The source array</param>
<param name="Output">The destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR256(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1465">
<summary>
Block XOR 32 bytes
</summary>

<param name="Input">The source array</param>
<param name="Output">The destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XOR256(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1473">
<summary>
Block XOR 32 bytes
</summary>

<param name="Input">The source array</param>
<param name="InOffset">Offset within the source array</param>
<param name="Output">The destination array</param>
<param name="OutOffset">Offset within the destination array</param>
</member>
<member name="M:CEX.Utility.IntUtils.XORBLK(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\intutils.h" line="1483">
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
<member name="F:Begin" decl="false" source="c:\users\john\documents\github\cex\engine\seekorigin.h" line="12">
<summary>
Start at the beginning of the stream
</summary>
</member>
<member name="F:Current" decl="false" source="c:\users\john\documents\github\cex\engine\seekorigin.h" line="16">
<summary>
Start at the streams current position
</summary>
</member>
<member name="F:End" decl="false" source="c:\users\john\documents\github\cex\engine\seekorigin.h" line="20">
<summary>
Start at the end of the stream
</summary>
</member>
<member name="T:CEX.IO.SeekOrigin" decl="false" source="c:\users\john\documents\github\cex\engine\seekorigin.h" line="7">
<summary>
Seek origin position flags
</summary>
</member>
<member name="T:CEX.Exception.CryptoProcessingException" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoprocessingexception.h" line="8">
<summary>
Generalized cryptographic error container
</summary>
</member>
<member name="M:CEX.Exception.CryptoProcessingException.Message" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoprocessingexception.h" line="18">
<summary>
Get/Set: The message associated with the error
</summary>
</member>
<member name="M:CEX.Exception.CryptoProcessingException.Origin" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoprocessingexception.h" line="23">
<summary>
Get/Set: The origin of the exception in the format Class
</summary>
</member>
<member name="M:CEX.Exception.CryptoProcessingException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoprocessingexception.h" line="29">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoProcessingException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptoprocessingexception.h" line="40">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="T:CEX.IO.IByteStream" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="12">
<summary>
Data stream object interface
</summary>
</member>
<member name="M:CEX.IO.IByteStream.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="20">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="25">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.IO.IByteStream.CanRead" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="32">
<summary>
Get: The stream can be read
</summary>
</member>
<member name="M:CEX.IO.IByteStream.CanSeek" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="37">
<summary>
Get: The stream is seekable
</summary>
</member>
<member name="M:CEX.IO.IByteStream.CanWrite" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="42">
<summary>
Get: The stream can be written to
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Length" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="47">
<summary>
Get: The stream length
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Position" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="52">
<summary>
Get: The streams current position
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Close" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="59">
<summary>
Close and flush the stream
</summary>
</member>
<member name="M:CEX.IO.IByteStream.CopyTo(CEX.IO.IByteStream*)" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="64">
<summary>
Copy this stream to another stream
</summary>

<param name="Destination">The destination stream</param>
</member>
<member name="M:CEX.IO.IByteStream.Destroy" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="71">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Flush" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="76">
<summary>
Write the stream to disk
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Read(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="81">
<summary>
Reads a portion of the stream into the buffer
</summary>

<param name="Buffer">The output buffer receiving the bytes</param>
<param name="Offset">Offset within the output buffer at which to begin</param>
<param name="Count">The number of bytes to read</param>

<returns>The number of bytes processed</returns>
</member>
<member name="M:CEX.IO.IByteStream.ReadByte" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="92">
<summary>
Read a single byte from the stream
</summary>

<returns>The byte value</returns>
</member>
<member name="M:CEX.IO.IByteStream.Reset" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="99">
<summary>
Reset and initialize the underlying digest
</summary>
</member>
<member name="M:CEX.IO.IByteStream.Seek(System.UInt32,&lt;unknown type&gt;)" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="104">
<summary>
Seek to a position within the stream
</summary>

<param name="Offset">The offset position</param>
<param name="Origin">The starting point</param>
</member>
<member name="M:CEX.IO.IByteStream.SetLength(System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="112">
<summary>
Set the length of the stream
</summary>

<param name="Length">The desired length</param>
</member>
<member name="M:CEX.IO.IByteStream.Write(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="119">
<summary>
Writes a buffer into the stream
</summary>

<param name="Buffer">The buffer to write to the stream</param>
<param name="Offset">Offset within the output buffer at which to begin</param>
<param name="Count">The number of bytes to write</param>

<returns>The number of bytes written</returns>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if Output array is too small</exception>
</member>
<member name="M:CEX.IO.IByteStream.WriteByte(System.Byte)" decl="false" source="c:\users\john\documents\github\cex\engine\ibytestream.h" line="132">
<summary>
Write a single byte from the stream
</summary>

<returns>The byte value</returns>
</member>
<member name="T:CEX.IO.MemoryStream" decl="false" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="8">
<summary>
Write data to a byte array
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.CanRead" decl="false" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="22">
<summary>
Get: The stream can be read
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.CanSeek" decl="false" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="27">
<summary>
Get: The stream is seekable
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.CanWrite" decl="false" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="32">
<summary>
Get: The stream can be written to
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.Length" decl="false" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="37">
<summary>
Get: The stream length
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.Position" decl="false" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="42">
<summary>
Get: The streams current position
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.ToArray" decl="false" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="47">
<summary>
Get: The underlying stream
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="54">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.#ctor(System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="65">
<summary>
Initialize this class; setting the streams length
</summary>

<param name="Length">The reserved length of the stream</param>
</member>
<member name="M:CEX.IO.MemoryStream.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="79">
<summary>
Initialize this class; setting a byte array as the streams content
</summary>

<param name="DataArray">The array used to initialize the stream</param>
</member>
<member name="M:CEX.IO.MemoryStream.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="92">
<summary>
Initialize this class (Copy constructor); copy a portion of a byte array to the streams content
</summary>

<param name="DataArray">The array used to initialize the stream</param>
<param name="Offset">The offset in the Data array at which to begin copying</param>
<param name="Length">The number of bytes to copy</param>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if the offset or length values are invalid</exception>
</member>
<member name="M:CEX.IO.MemoryStream.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="116">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.Close" decl="true" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="125">
<summary>
Close and flush the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Not implemented exception</exception>
</member>
<member name="M:CEX.IO.MemoryStream.CopyTo(CEX.IO.IByteStream*)" decl="true" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="132">
<summary>
Copy this stream to another stream
</summary>

<param name="Destination">The destination stream</param>
</member>
<member name="M:CEX.IO.MemoryStream.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="139">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.Flush" decl="true" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="144">
<summary>
Write the stream to disk
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Not implemented exception</exception>
</member>
<member name="M:CEX.IO.MemoryStream.Read(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="151">
<summary>
Reads a portion of the stream into the buffer
</summary>

<param name="Buffer">The output buffer receiving the bytes</param>
<param name="Offset">Offset within the output buffer at which to begin</param>
<param name="Count">The number of bytes to read</param>

<returns>The number of bytes processed</returns>
</member>
<member name="M:CEX.IO.MemoryStream.ReadByte" decl="true" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="162">
<summary>
Read a single byte from the stream
</summary>

<returns>The byte value</returns>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if the output array is too short</exception>
</member>
<member name="M:CEX.IO.MemoryStream.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="171">
<summary>
Reset and initialize the underlying stream to zero
</summary>
</member>
<member name="M:CEX.IO.MemoryStream.Seek(System.UInt32,&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="176">
<summary>
Seek to a position within the stream
</summary>

<param name="Offset">The offset position</param>
<param name="Origin">The starting point</param>
</member>
<member name="M:CEX.IO.MemoryStream.SetLength(System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="184">
<summary>
Set the length of the stream
</summary>

<param name="Length">The desired length</param>
</member>
<member name="M:CEX.IO.MemoryStream.Write(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="191">
<summary>
Writes a buffer into the stream
</summary>

<param name="Buffer">The output buffer to write to the stream</param>
<param name="Offset">Offset within the output buffer at which to begin</param>
<param name="Count">The number of bytes to write</param>

<returns>The number of bytes processed</returns>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if Output array is too small</exception>
</member>
<member name="M:CEX.IO.MemoryStream.WriteByte(System.Byte)" decl="true" source="c:\users\john\documents\github\cex\engine\memorystream.h" line="204">
<summary>
Write a single byte from the stream
</summary>

<returns>The byte value</returns>
</member>
<member name="T:CEX.IO.StreamWriter" decl="false" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="8">
<summary>
Write integer values to a byte array
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Length" decl="false" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="19">
<summary>
The length of the data
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Position" decl="false" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="24">
<summary>
The current position within the data
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.#ctor(System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="29">
<summary>
Initialize this class
</summary>

<param name="Length">The length of the underlying stream</param>
</member>
<member name="M:CEX.IO.StreamWriter.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="41">
<summary>
Initialize this class with a byte array
</summary>

<param name="DataArray">The byte array to write data to</param>
</member>
<member name="M:CEX.IO.StreamWriter.#ctor(CEX.IO.MemoryStream*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="53">
<summary>
Initialize this class with a MemoryStream
</summary>

<param name="DataStream">The MemoryStream to write data to</param>
</member>
<member name="M:CEX.IO.StreamWriter.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="65">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="73">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.GetBytes" decl="true" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="78">
<summary>
Returns the entire array of raw bytes from the stream
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.GetStream" decl="true" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="83">
<summary>
Returns the base MemoryStream object
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Write(System.Byte)" decl="true" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="88">
<summary>
Write an 8bit integer to the base stream
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Write(System.Int16)" decl="true" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="93">
<summary>
Write a 16bit integer to the base stream
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Write(System.UInt16)" decl="true" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="98">
<summary>
Write a 16bit unsigned integer to the base stream
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Write(System.Int32)" decl="true" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="103">
<summary>
Write a 32bit integer to the base stream
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Write(System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="108">
<summary>
Write a 32bit unsigned integer to the base stream
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Write(System.Int32!System.Runtime.CompilerServices.IsLong)" decl="true" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="113">
<summary>
Write a 64bit integer to the base stream
</summary>
</member>
<member name="M:CEX.IO.StreamWriter.Write(System.UInt64)" decl="true" source="c:\users\john\documents\github\cex\engine\streamwriter.h" line="118">
<summary>
Write a 64bit unsigned integer to the base stream
</summary>
</member>
<member name="T:CEX.IO.StreamReader" decl="false" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="8">
<summary>
Methods for reading integer types from a binary stream
</summary>
</member>
<member name="M:CEX.IO.StreamReader.Length" decl="false" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="19">
<summary>
The length of the data
</summary>
</member>
<member name="M:CEX.IO.StreamReader.Position" decl="false" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="24">
<summary>
The current position within the data
</summary>
</member>
<member name="M:CEX.IO.StreamReader.#ctor(CEX.IO.MemoryStream!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="29">
<summary>
Initialize this class with a byte array
</summary>

<param name="DataStream">MemoryStream to read</param>
</member>
<member name="M:CEX.IO.StreamReader.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="40">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.IO.StreamReader.ReadByte" decl="true" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="47">
<summary>
Read a single byte from the stream
</summary>

<returns>The byte value</returns>
</member>
<member name="M:CEX.IO.StreamReader.ReadBytes(System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="54">
<summary>
Reads a portion of the stream into the buffer
</summary>

<param name="Length">The number of bytes to read</param>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadInt16" decl="true" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="63">
<summary>
Reads a 16 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadUInt16" decl="true" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="70">
<summary>
Reads an unsigned 16 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadInt32" decl="true" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="77">
<summary>
Reads a 32 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadUInt32" decl="true" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="84">
<summary>
Reads an unsigned 32 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadInt64" decl="true" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="91">
<summary>
Reads a 64 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadUInt64" decl="true" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="98">
<summary>
Reads an unsigned 64 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadWord32" decl="true" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="105">
<summary>
Reads an unsigned 32 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="M:CEX.IO.StreamReader.ReadWord64" decl="true" source="c:\users\john\documents\github\cex\engine\streamreader.h" line="112">
<summary>
Reads an unsigned 64 bit integer from the stream
</summary>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if source array is too small</exception>
</member>
<member name="T:CEX.Common.KeyParams" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="11">
<summary>
KeyParams: A Symmetric Cipher Key and Vector Container class.
</summary>
</member>
<member name="M:CEX.Common.KeyParams.Key" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="24">
<summary>
Get: The cipher Key
</summary>
</member>
<member name="M:CEX.Common.KeyParams.Key" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="29">
<summary>
Set: The cipher Key
</summary>
</member>
<member name="M:CEX.Common.KeyParams.IV" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="34">
<summary>
Get: Cipher Initialization Vector
</summary>
</member>
<member name="M:CEX.Common.KeyParams.IV" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="39">
<summary>
Set: Cipher Initialization Vector
</summary>
</member>
<member name="M:CEX.Common.KeyParams.Ikm" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="44">
<summary>
Get: Input Keying Material
</summary>
</member>
<member name="M:CEX.Common.KeyParams.Ikm" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="49">
<summary>
Set: Input Keying Material
</summary>
</member>
<member name="M:CEX.Common.KeyParams.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="54">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.Common.KeyParams.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="66">
<summary>
Initialize this class with a Cipher Key
</summary>

<param name="Key">Cipher Key</param>
</member>
<member name="M:CEX.Common.KeyParams.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="80">
<summary>
Initialize this class with a Cipher Key, and IV
</summary>

<param name="Key">Cipher Key</param>
<param name="IV">Cipher IV</param>
</member>
<member name="M:CEX.Common.KeyParams.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="94">
<summary>
Initialize this class with a Cipher Key, IV, and IKM
</summary>

<param name="Key">Cipher Key</param>
<param name="IV">Cipher IV</param>
<param name="Ikm">Input Key Material</param>
</member>
<member name="M:CEX.Common.KeyParams.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="110">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Common.KeyParams.Clone" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="118">
<summary>
Create a shallow copy of this KeyParams class
</summary>
</member>
<member name="M:CEX.Common.KeyParams.DeepCopy" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="126">
<summary>
Create a deep copy of this KeyParams class
</summary>
</member>
<member name="M:CEX.Common.KeyParams.Destroy" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="145">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Common.KeyParams.Equals(CEX.Common.KeyParams*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="163">
<summary>
Compare this KeyParams instance with another
</summary>

<param name="Obj">KeyParams to compare</param>

<returns>Returns true if equal</returns>
</member>
<member name="M:CEX.Common.KeyParams.DeSerialize(CEX.IO.MemoryStream*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="182">
<summary>
Deserialize a KeyParams class
</summary>

<param name="KeyStream">Stream containing the KeyParams data</param>

<returns>A populated KeyParams class</returns>
</member>
<member name="M:CEX.Common.KeyParams.Serialize(CEX.Common.KeyParams*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\keyparams.h" line="209">
<summary>
Serialize a KeyParams class
</summary>

<param name="KeyObj">A KeyParams class</param>

<returns>A stream containing the KeyParams data</returns>
</member>
<member name="T:CEX.Cipher.Symmetric.Block.IBlockCipher" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="38">
<summary>
Block Cipher Interface
</summary> 
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="46">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="51">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="58">
<summary>
Get: Unit block size of internal cipher in bytes
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="63">
<summary>
Get: The block ciphers type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.IsEncryption" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="68">
<summary>
Get: True is initialized for encryption, false for decryption.
<para>Value set in <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/>.</para>
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.IsInitialized" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="74">
<summary>
Get: Cipher is ready to transform data
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.LegalKeySizes" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="79">
<summary>
Get: List of available legal key sizes
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.LegalRounds" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="84">
<summary>
Get: Available diffusion round assignments
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Name" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="89">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Rounds" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="94">
<summary>
Get: The number of diffusion rounds processed by the transform
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.DecryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="101">
<summary>
Decrypt a single block of bytes.
<para><see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
Input and Output arrays must be at least <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.BlockSize"/> in length.</para>
</summary>

<param name="Input">Encrypted bytes</param>
<param name="Output">Decrypted bytes</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.DecryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="111">
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
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Destroy" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="123">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.EncryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="128">
<summary>
Encrypt a block of bytes.
<para><see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
Input and Output array lengths must be at least <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.BlockSize"/> in length.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.EncryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="138">
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
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="150">
<summary>
Initialize the Cipher
</summary>

<param name="Encryption">Using Encryption or Decryption mode</param>
<param name="KeyParam">Cipher key container. <para>The <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.LegalKeySizes"/> property contains valid sizes.</para></param>

<exception cref="T:CEX.Exception.CryptoSymmetricCipherException">Thrown if a null or invalid key is used</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="160">
<summary>
Transform a block of bytes.
<para><see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.
Input and Output array lengths must be at least <see cref="M:CEX.Cipher.Symmetric.Block.IBlockCipher.BlockSize"/> in length.</para>
</summary>

<param name="Input">Input bytes to Transform or Decrypt</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.IBlockCipher.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\iblockcipher.h" line="170">
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
<member name="T:CEX.Cipher.Symmetric.Block.Mode.ICipherMode" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="35">
<summary>
Cipher Mode Interface
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="43">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="48">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="55">
<summary>
Get: Unit block size of internal cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Engine" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="60">
<summary>
Get: Underlying Cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="65">
<summary>
Get: The cipher modes type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.IsEncryption" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="70">
<summary>
Get: Initialized for encryption, false for decryption
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.IsInitialized" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="75">
<summary>
Get: Cipher is ready to transform data
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.IsParallel" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="80">
<summary>
Get: Automatic processor parallelization
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.IV" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="85">
<summary>
Get: The current state of the initialization Vector
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.LegalKeySizes" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="90">
<summary>
Get: List of available legal key sizes
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Name" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="95">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ParallelBlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="100">
<summary>
Get: Parallel block size. Must be a multiple of <see cref="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ParallelMinimumSize"/>.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ParallelMaximumSize" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="105">
<summary>
Get: Maximum input size with parallel processing
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ParallelMinimumSize" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="110">
<summary>
Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ProcessorCount" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="115">
<remarks>
Get: Processor count
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Destroy" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="122">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="127">
<summary>
Initialize the Cipher
</summary>

<param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
<param name="KeyParam">The KeyParams containing key and vector</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="135">
<summary>
Transform a block of bytes. 
<para>Parallel capable function if Output array length is at least equal to <see cref="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ParallelMinimumSize"/>.
Initialize() must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\iciphermode.h" line="145">
<summary>
Transform a block of bytes with offset parameters.  
<para>Parallel capable function if Output array length is at least equal to <see cref="M:CEX.Cipher.Symmetric.Block.Mode.ICipherMode.ParallelMinimumSize"/>.
Initialize() must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="T:CEX.Helper.CipherModeFromName" decl="false" source="c:\users\john\documents\github\cex\engine\ciphermodefromname.h" line="10">
<summary>
CipherModeFromName: Get a Cipher Mode instance from it's enumeration name.
</summary>
</member>
<member name="M:CEX.Helper.CipherModeFromName.GetInstance(&lt;unknown type&gt;,CEX.Cipher.Symmetric.Block.IBlockCipher*)" decl="true" source="c:\users\john\documents\github\cex\engine\ciphermodefromname.h" line="16">
<summary>
Get an Cipher Mode instance by name using default parameters
</summary>

<param name="CipherType">The cipher mode enumeration name</param>
<param name="Engine">The block cipher instance</param>

<returns>An initialized digest</returns>

<exception cref="T:CEX.Exception.CryptoException">Thrown if the enumeration name is not supported</exception>
</member>
<member name="T:CEX.Cipher.Symmetric.Block.Mode.CTR" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="36">
<summary>
Implements a Parallel Segmented Counter Mode: CTR
</summary> 

<example>
<description>Example using an <c>ICipherMode</c> interface:</description>
<code>
CTR cipher(new RDX());
// initialize for encryption
cipher.Initialize(true, KeyParams(Key, IV));
// encrypt a block
cipher.Transform(Input, Output);
</code>
</example>

<seealso cref="N:CEX.Cipher.Symmetric.Block"/>
<seealso cref="T:CEX.Cipher.Symmetric.Block.Mode.ICipherMode"/>
<seealso cref="T:CEX.Enumeration.BlockCiphers"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>In CTR mode, both encryption and decryption can be processed in parallel.</description></item>
<item><description>Parallel processing is enabled by passing a block size of <see cref="M:CEX.Cipher.Symmetric.Block.Mode.CTR.ParallelBlockSize"/> to the transform.</description></item>
<item><description>ParallelBlockSize must be divisible by <see cref="M:CEX.Cipher.Symmetric.Block.Mode.CTR.ParallelMinimumSize"/>.</description></item>
<item><description>Parallel block calculation ex. <c>int blocklen = (data.size() / cipher.ParallelMinimumSize()) * 100</c></description></item>
</list>

<description>Guiding Publications:</description>
<list type="number">
<item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="91">
<summary>
Get: Unit block size of internal cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.Engine" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="96">
<summary>
Get: Underlying Cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="101">
<summary>
Get: The cipher modes type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.IsEncryption" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="106">
<summary>
Get: Initialized for encryption, false for decryption
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.IsInitialized" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="111">
<summary>
Get: Cipher is ready to transform data
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.IsParallel" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="116">
<summary>
Get/Set: Automatic processor parallelization
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.IV" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="121">
<summary>
Get: The current state of the initialization Vector
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.LegalKeySizes" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="126">
<summary>
Get: Available Encryption Key Sizes in bytes
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.Name" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="131">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.ParallelBlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="136">
<summary>
Get/Set: Parallel block size. Must be a multiple of <see cref="M:CEX.Cipher.Symmetric.Block.Mode.CTR.ParallelMinimumSize"/>.
<para>The parallel block size is calculated automatically based on the number of available processors on the system (n * 64kb).</para>
</summary>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, 
or block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.ParallelMaximumSize" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="145">
<summary>
Get: Maximum input size with parallel processing
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.ParallelMinimumSize" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="150">
<summary>
Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.ProcessorCount" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="155">
<remarks>
Get: Processor count
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.#ctor(CEX.Cipher.Symmetric.Block.IBlockCipher*)" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="162">
<summary>
Initialize the Cipher
</summary>

<param name="Cipher">Underlying encryption algorithm</param>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a null Cipher is used</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\ctr.h" line="186">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\ctr.h" line="196">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\ctr.h" line="201">
<summary>
Initialize the Cipher
</summary>

<param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
<param name="KeyParam">The KeyParams containing key and std::vector</param>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a null Key or IV is used</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\ctr.h" line="211">
<summary>
Process an array of bytes. 
<para>Parallel capable function if Output array length is at least equal to <see cref="M:CEX.Cipher.Symmetric.Block.Mode.CTR.ParallelMinimumSize"/>. 
This method processes the entire array; used when processing small data or buffers from a larger source.
Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CTR.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\ctr.h" line="222">
<summary>
Transform one block of bytes with offset parameters.  
<para>Parallel capable function if Output array length is at least equal to <see cref="M:CEX.Cipher.Symmetric.Block.Mode.CTR.ParallelMinimumSize"/>. 
Method will process a single block from the array of either ParallelBlockSize or Blocksize depending on IsParallel property setting.
Partial blocks are permitted with both parallel and linear operation modes.
Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Transformed bytes</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="T:CEX.Cipher.Symmetric.Block.Mode.CBC" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="36">
<summary>
Implements a Cipher Block Chaining Mode: CBC
</summary> 

<example>
<description>Example using an <c>ICipherMode</c> interface:</description>
<code>
CBC cipher(new RDX());
// initialize for encryption
cipher.Initialize(true, KeyParams(Key, IV));
// encrypt a block
cipher.Transform(Input, Output);
</code>
</example>

<seealso cref="N:CEX.Cipher.Symmetric.Block"/>
<seealso cref="T:CEX.Cipher.Symmetric.Block.Mode.ICipherMode"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>In CFB mode, only decryption can be processed in parallel.</description></item>
<item><description>Parallel processing is enabled on decryption by passing a block size of ParallelBlockSize to the transform.</description></item>
<item><description>ParallelBlockSize must be divisible by ParallelMinimumSize.</description></item>
<item><description>Parallel block calculation ex. <c>int blocklen = (data.size() / cipher.ParallelMinimumSize()) * 100</c></description></item>
</list>

<description>Guiding Publications:</description>
<list type="number">
<item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="90">
<summary>
Get: Unit block size of internal cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.Engine" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="95">
<summary>
Get: Underlying Cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="100">
<summary>
Get: The cipher modes type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.IsEncryption" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="105">
<summary>
Get: Initialized for encryption, false for decryption
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.IsInitialized" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="110">
<summary>
Get: Cipher is ready to transform data
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.IsParallel" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="115">
<summary>
Get/Set: Automatic processor parallelization
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.IV" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="120">
<summary>
Get: The current state of the initialization Vector
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.LegalKeySizes" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="125">
<summary>
Get: Available Encryption Key Sizes in bytes
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.Name" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="130">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.ParallelBlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="135">
<summary>
Get/Set: Parallel block size. Must be a multiple of <see cref="M:CEX.Cipher.Symmetric.Block.Mode.CBC.ParallelMinimumSize"/>.
<para>The parallel block size is calculated automatically based on the number of available processors on the system (n * 64kb).</para>
</summary>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, 
or block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.ParallelMaximumSize" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="144">
<summary>
Get: Maximum input size with parallel processing
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.ParallelMinimumSize" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="149">
<summary>
Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.ProcessorCount" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="154">
<remarks>
Get: Processor count
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.#ctor(CEX.Cipher.Symmetric.Block.IBlockCipher*)" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="162">
<summary>
Initialize the Cipher
</summary>

<param name="Cipher">Underlying encryption cipher</param>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a null Cipher is used</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\cbc.h" line="186">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.DecryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\cbc.h" line="196">
<summary>
Decrypt a block of bytes.
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Encrypted bytes</param>
<param name="Output">Decrypted bytes</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.DecryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\cbc.h" line="205">
<summary>
Decrypt a block of bytes with offset parameters. 
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Encrypted bytes</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Decrypted bytes</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\cbc.h" line="216">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.EncryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\cbc.h" line="221">
<summary>
Encrypt a block of bytes. 
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.EncryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\cbc.h" line="230">
<summary>
Encrypt a block of bytes with offset parameters. 
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\cbc.h" line="241">
<summary>
Initialize the Cipher
</summary>

<param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
<param name="KeyParam">KeyParam containing key and std::vector</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\cbc.h" line="249">
<summary>
Transform a block of bytes. Parallel capable in Decryption mode.
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CBC.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\cbc.h" line="258">
<summary>
Transform a block of bytes with offset parameters.
<para> Parallel capable in Decryption mode.
Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="T:CEX.Cipher.Symmetric.Block.Mode.CFB" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="36">
<summary>
Implements a Cipher FeedBack Mode: CFB
</summary>

<example>
<description>Example using an <c>ICipherMode</c> interface:</description>
<code>
CFB cipher(new RDX());
// initialize for encryption
cipher.Initialize(true, KeyParams(Key, IV));
// encrypt a block
cipher.Transform(Input, Output);
</code>
</example>

<seealso cref="N:CEX.Cipher.Symmetric.Block"/>
<seealso cref="T:CEX.Cipher.Symmetric.Block.Mode.ICipherMode"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>In CFB mode, only decryption can be processed in parallel.</description></item>
<item><description>Parallel processing is enabled on decryption by passing a block size of ParallelBlockSize to the transform.</description></item>
<item><description>ParallelBlockSize must be divisible by ParallelMinimumSize.</description></item>
<item><description>Parallel block calculation ex. <c>int blocklen = (data.size() / cipher.ParallelMinimumSize()) * 100</c></description></item>
</list>

<description>Guiding Publications:</description>
<list type="number">
<item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="89">
<summary>
Get: Unit block size of internal cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.Engine" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="94">
<summary>
Get: Underlying Cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="99">
<summary>
Get: The cipher modes type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.IsEncryption" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="104">
<summary>
Get: Initialized for encryption, false for decryption
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.IsInitialized" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="109">
<summary>
Get: Cipher is ready to transform data
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.IsParallel" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="114">
<summary>
Get/Set: Automatic processor parallelization
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.IV" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="119">
<summary>
Get: The current state of the initialization Vector
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.LegalKeySizes" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="124">
<summary>
Get: Available Encryption Key Sizes in bytes
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.Name" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="129">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.ParallelBlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="134">
<summary>
Get/Set: Parallel block size. Must be a multiple of <see cref="M:CEX.Cipher.Symmetric.Block.Mode.CFB.ParallelMinimumSize"/>.
<para>The parallel block size is calculated automatically based on the number of available processors on the system (n * 64kb).</para>
</summary>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, 
or block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.ParallelMaximumSize" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="143">
<summary>
Get: Maximum input size with parallel processing
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.ParallelMinimumSize" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="148">
<summary>
Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.ProcessorCount" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="153">
<remarks>
Get: Processor count
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.#ctor(CEX.Cipher.Symmetric.Block.IBlockCipher*,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="160">
<summary>
Initialize the Cipher
</summary>

<param name="Cipher">Underlying encryption algorithm</param>
<param name="BlockSizeBits">Block size in bits; minimum is 8, or 1 byte. Maximum is Cipher block size in bits</param>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a null Cipher or valid block size is used</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\cfb.h" line="191">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\cfb.h" line="201">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\cfb.h" line="206">
<summary>
Initialize the Cipher
</summary>

<param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
<param name="KeyParam">KeyParams containing key and std::vector</param>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a null Key or IV is used</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\cfb.h" line="216">
<summary>
Transform a block of bytes. 
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\cfb.h" line="225">
<summary>
Transform a block of bytes with offset parameters. 
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.DecryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\cfb.h" line="236">
<summary>
Decrypt a single block of bytes.
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Encrypted bytes</param>
<param name="Output">Decrypted bytes</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.DecryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\cfb.h" line="245">
<summary>
Decrypt a block of bytes with offset parameters.
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Encrypted bytes</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Decrypted bytes</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.EncryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\cfb.h" line="256">
<summary>
Encrypt a block of bytes.
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.CFB.EncryptBlock(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\cfb.h" line="265">
<summary>
Encrypt a block of bytes with offset parameters.
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="T:CEX.Cipher.Symmetric.Block.Mode.OFB" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="36">
<summary>
Implements a Cipher FeedBack Mode: OFB
</summary>

<example>
<description>Example using an <c>ICipherMode</c> interface:</description>
<code>
OFB cipher(new RDX());
// initialize for encryption
cipher.Initialize(true, KeyParams(Key, IV));
// encrypt a block
cipher.Transform(Input, Output);
</code>
</example>

<seealso cref="N:CEX.Cipher.Symmetric.Block"/>
<seealso cref="T:CEX.Enumeration.BlockCiphers"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>OFB is not a parallel capable cipher mode.</description></item>
</list>

<description>Guiding Publications:</description>
<list type="number">
<item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="83">
<summary>
Get: Unit block size of internal cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.Engine" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="88">
<summary>
Get: Underlying Cipher
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="93">
<summary>
Get: The cipher modes type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.IsEncryption" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="98">
<summary>
Get: Initialized for encryption, false for decryption
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.IsInitialized" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="103">
<summary>
Get: Cipher is ready to transform data
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.IsParallel" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="108">
<summary>
Get/Set: Automatic processor parallelization
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.IV" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="113">
<summary>
Get: The current state of the initialization Vector
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.LegalKeySizes" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="118">
<summary>
Get: Available Encryption Key Sizes in bytes
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.Name" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="123">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.ParallelBlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="128">
<summary>
Get/Set: Parallel block size. Must be a multiple of <see cref="M:CEX.Cipher.Symmetric.Block.Mode.OFB.ParallelMinimumSize"/>.
<para>The parallel block size is calculated automatically based on the number of available processors on the system (n * 64kb).</para>
</summary>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, 
or block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.ParallelMaximumSize" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="137">
<summary>
Get: Maximum input size with parallel processing
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.ParallelMinimumSize" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="142">
<summary>
Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.ProcessorCount" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="147">
<remarks>
Get: Processor count
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.#ctor(CEX.Cipher.Symmetric.Block.IBlockCipher*,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="154">
<summary>
Initialize the Cipher
</summary>

<param name="Cipher">Underlying encryption algorithm</param>
<param name="BlockSizeBits">Block size in bits; minimum is 8, or 1 byte. Maximum is Cipher block size in bits</param>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a null Cipher or valid block size is used</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\ofb.h" line="183">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\ofb.h" line="193">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.Initialize(System.Boolean,CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\ofb.h" line="198">
<summary>
Initialize the Cipher
</summary>

<param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
<param name="KeyParam">KeyParams containing key and vector</param>

<exception cref="T:CEX.Exception.CryptoCipherModeException">Thrown if a null Key or IV is used</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\ofb.h" line="208">
<summary>
Transform a block of bytes. 
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="Output">Output product of Transform</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Block.Mode.OFB.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\ofb.h" line="217">
<summary>
Transform a block of bytes with offset parameters. 
<para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
</members>
</doc>