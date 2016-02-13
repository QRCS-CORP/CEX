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
<member name="T:CEX.Helper.DigestFromName" decl="false" source="c:\users\john\documents\github\cex\engine\digestfromname.h" line="10">
<summary>
DigestFromName: Get a Message Digest instance from it's enumeration name.
</summary>
</member>
<member name="M:CEX.Helper.DigestFromName.GetInstance(&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\github\cex\engine\digestfromname.h" line="16">
<summary>
Get a Digest instance by name
</summary>

<param name="DigestType">The message digest enumeration name</param>

<returns>An initialized digest</returns>

<exception cref="T:CEX.Exception.CryptoException">Thrown if the enumeration name is not supported</exception>
</member>
<member name="T:CEX.Digest.Blake256" decl="false" source="c:\users\john\documents\github\cex\engine\blake256.h" line="40">
<summary>
Blake256: An implementation of the Blake digest with a 256 bit return size
</summary> 

<example>
<description>Example using the ComputeHash method:</description>
<code>
Blake256 digest;
std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
// compute a hash
digest.ComputeHash(Input, hash);
</code>
</example>

<seealso cref="T:CEX.Digest.IDigest"/>
<seealso cref="T:CEX.Enumeration.Digests"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>Block size is 32 bytes, (256 bits).</description></item>
<item><description>Digest size is 32 bytes, (256 bits).</description></item>
<item><description>The <see cref="M:CEX.Digest.Blake256.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> method wraps the <see cref="M:CEX.Digest.Blake256.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)"/> and DoFinal methods.</description>/&gt;</item>
<item><description>The <see cref="M:CEX.Digest.Blake256.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)"/> method resets the internal state.</description></item>
</list>

<description>Guiding Publications:</description>
<list type="number">
<item><description>NIST <a href="https://131002.net/blake">SHA3 Proposal Blake</a>.</description></item>
<item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3: Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
<item><description>SHA3 Submission in C: <a href="https://131002.net/blake/blake_ref.c">blake_ref.c</a>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Digest.Blake256.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\blake256.h" line="98">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Digest.Blake256.DigestSize" decl="false" source="c:\users\john\documents\github\cex\engine\blake256.h" line="103">
<summary>
Get: Size of returned digest in bytes
</summary>
</member>
<member name="M:CEX.Digest.Blake256.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\blake256.h" line="108">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.Blake256.Name" decl="false" source="c:\users\john\documents\github\cex\engine\blake256.h" line="113">
<summary>
Get: Digest name
</summary>
</member>
<member name="M:CEX.Digest.Blake256.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\blake256.h" line="120">
<summary>
Initialize the digest
</summary>
</member>
<member name="M:CEX.Digest.Blake256.#ctor(std.vector&lt;System.UInt32,std.allocator&lt;System.UInt32&gt;&gt;)" decl="false" source="c:\users\john\documents\github\cex\engine\blake256.h" line="137">
<summary>
Initialize the class with a salt value
</summary>

<param name="Salt">The optional salt value; must be 4 unsigned ints in length</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the salt length is invalid</exception>
</member>
<member name="M:CEX.Digest.Blake256.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\blake256.h" line="164">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Digest.Blake256.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\blake256.h" line="174">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the input buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Blake256.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\blake256.h" line="185">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.Blake256.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\blake256.h" line="193">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.Blake256.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\blake256.h" line="198">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the output buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Blake256.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\blake256.h" line="210">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.Blake256.Update(System.Byte)" decl="true" source="c:\users\john\documents\github\cex\engine\blake256.h" line="215">
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
<member name="T:CEX.Digest.Blake512" decl="false" source="c:\users\john\documents\github\cex\engine\blake512.h" line="41">
<summary>
Blake512: An implementation of the Blake digest with a 512 bit return size
</summary> 

<example>
<description>Example using the ComputeHash method:</description>
<code>
Blake512 digest;
std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
// compute a hash
digest.ComputeHash(Input, hash);
</code>
</example>

<seealso cref="T:CEX.Digest.IDigest"/>
<seealso cref="T:CEX.Enumeration.Digests"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>Block size is 64 bytes, (512 bits).</description></item>
<item><description>Digest size is 64 bytes, (512 bits).</description></item>
<item><description>The <see cref="M:CEX.Digest.Blake512.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> method wraps the <see cref="M:CEX.Digest.Blake512.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)"/> and DoFinal methods</description>/&gt;</item>
<item><description>The <see cref="M:CEX.Digest.Blake512.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)"/> method resets the internal state.</description></item>
</list>

<description>Guiding Publications:</description>
<list type="number">
<item><description>NIST <a href="https://131002.net/blake">SHA3 Proposal Blake</a>.</description></item>
<item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3: Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
<item><description>SHA3 Submission in C: <a href="https://131002.net/blake/blake_ref.c">blake_ref.c</a>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Digest.Blake512.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\blake512.h" line="99">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Digest.Blake512.DigestSize" decl="false" source="c:\users\john\documents\github\cex\engine\blake512.h" line="104">
<summary>
Get: Size of returned digest in bytes
</summary>
</member>
<member name="M:CEX.Digest.Blake512.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\blake512.h" line="109">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.Blake512.Name" decl="false" source="c:\users\john\documents\github\cex\engine\blake512.h" line="114">
<summary>
Get: Digest name
</summary>
</member>
<member name="M:CEX.Digest.Blake512.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\blake512.h" line="121">
<summary>
Initialize the digest
</summary>
</member>
<member name="M:CEX.Digest.Blake512.#ctor(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;)" decl="false" source="c:\users\john\documents\github\cex\engine\blake512.h" line="138">
<summary>
Initialize the class with a salt value
</summary>

<param name="Salt">The optional salt value; must be 4 unsigned longs in length</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the salt length is invalid</exception>
</member>
<member name="M:CEX.Digest.Blake512.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\blake512.h" line="165">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Digest.Blake512.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\blake512.h" line="175">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the input buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Blake512.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\blake512.h" line="186">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.Blake512.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\blake512.h" line="194">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.Blake512.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\blake512.h" line="199">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the output buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Blake512.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\blake512.h" line="211">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.Blake512.Update(System.Byte)" decl="true" source="c:\users\john\documents\github\cex\engine\blake512.h" line="216">
<summary>
Update the message digest with a single byte
</summary>

<param name="Input">Input byte</param>
</member>
<member name="T:CEX.Digest.Keccak256" decl="false" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="41">
<summary>
Keccak256: An implementation of the SHA-3 Keccak digest
</summary>

<example>
<description>Example using the ComputeHash method:</description>
<code>
Keccak256 digest;
std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
// compute a hash
digest.ComputeHash(Input, hash);
</code>
</example>

<seealso cref="T:CEX.Digest.IDigest"/>
<seealso cref="T:CEX.Enumeration.Digests"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>Hash sizes are 28, 32, and 36 bytes (224, 256, and 288 bits).</description></item>
<item><description>Block sizes are 144, 128, and 136 bytes (1152, 1024, 1088 bits).</description></item>
<item><description>Use the <see cref="M:CEX.Digest.Keccak256.BlockSize"/> property to determine block sizes at runtime.</description></item>
<item><description>The <see cref="M:CEX.Digest.Keccak256.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> method wraps the <see cref="M:CEX.Digest.Keccak256.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)"/> and DoFinal methods.</description>/&gt;</item>
<item><description>The <see cref="M:CEX.Digest.Keccak256.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)"/> method resets the internal state.</description></item>
</list>

<list type="number">
<item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">Keccak Submission</a>.</description></item>
<item><description>SHA3 <a href="http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf">Keccak Slides</a>.</description></item>
<item><description>SHA3 <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Digest.Keccak256.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="88">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Digest.Keccak256.DigestSize" decl="false" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="93">
<summary>
Get: Size of returned digest in bytes
</summary>
</member>
<member name="M:CEX.Digest.Keccak256.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="98">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.Keccak256.Name" decl="false" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="103">
<summary>
Get: Digest name
</summary>
</member>
<member name="M:CEX.Digest.Keccak256.#ctor(System.Int32)" decl="false" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="110">
<summary>
Initialize the digest
</summary>

<param name="DigestSize">Digest return size in bits</param>
</member>
<member name="M:CEX.Digest.Keccak256.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="137">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Digest.Keccak256.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="147">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the input buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Keccak256.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="158">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.Keccak256.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="166">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.Keccak256.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="171">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the output buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Keccak256.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="183">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.Keccak256.Update(System.Byte)" decl="true" source="c:\users\john\documents\github\cex\engine\keccak256.h" line="188">
<summary>
Update the digest with a single byte
</summary>

<param name="Input">Input byte</param>
</member>
<member name="T:CEX.Digest.Keccak512" decl="false" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="41">
<summary>
Keccak512: An implementation of the SHA-3 Keccak digest
</summary>

<example>
<description>Example using an <c>IDigest</c> interface:</description>
<code>
Keccak512 digest;
std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
// compute a hash
digest.ComputeHash(Input, hash);
</code>
</example>

<seealso cref="T:CEX.Digest.IDigest"/>
<seealso cref="T:CEX.Enumeration.Digests"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>Hash sizes are 48 and 64 bytes (384 and 512 bits).</description></item>
<item><description>Block sizes are 104, and 72 bytes (832, 576 bits).</description></item>
<item><description>Use the <see cref="M:CEX.Digest.Keccak512.BlockSize"/> property to determine block sizes at runtime.</description></item>
<item><description>The <see cref="M:CEX.Digest.Keccak512.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> method wraps the <see cref="M:CEX.Digest.Keccak512.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)"/> and DoFinal methods.</description>/&gt;</item>
<item><description>The <see cref="M:CEX.Digest.Keccak512.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)"/> method resets the internal state.</description></item>
</list>

<description>Guiding Publications:</description>
<list type="number">
<item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">Keccak Submission</a>.</description></item>
<item><description>SHA3 <a href="http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf">Keccak Slides</a>.</description></item>
<item><description>SHA3 <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
</list>&gt;
</remarks>
</member>
<member name="M:CEX.Digest.Keccak512.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="89">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Digest.Keccak512.DigestSize" decl="false" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="94">
<summary>
Get: Size of returned digest in bytes
</summary>
</member>
<member name="M:CEX.Digest.Keccak512.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="99">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.Keccak512.Name" decl="false" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="104">
<summary>
Get: Digest name
</summary>
</member>
<member name="M:CEX.Digest.Keccak512.#ctor(System.Int32)" decl="false" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="111">
<summary>
Initialize the digest
</summary>

<param name="DigestSize">Digest return size in bits</param>
</member>
<member name="M:CEX.Digest.Keccak512.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="136">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Digest.Keccak512.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="146">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the input buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Keccak512.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="157">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.Keccak512.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="165">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.Keccak512.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="170">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the output buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Keccak512.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="182">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.Keccak512.Update(System.Byte)" decl="true" source="c:\users\john\documents\github\cex\engine\keccak512.h" line="187">
<summary>
Update the digest with a single byte
</summary>

<param name="Input">Input byte</param>
</member>
<member name="T:CEX.Digest.SHA256" decl="false" source="c:\users\john\documents\github\cex\engine\sha256.h" line="41">
<summary>
SHA256: An implementation of the SHA-2 digest with a 256 bit digest return size
</summary> 

<example>
<description>Example using the ComputeHash method:</description>
<code>
SHA256 digest;
std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
// compute a hash
digest.ComputeHash(Input, hash);
</code>
</example>

<seealso cref="T:CEX.Digest.IDigest"/>
<seealso cref="T:CEX.Enumeration.Digests"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>Block size is 64 bytes, (512 bits).</description></item>
<item><description>Digest size is 32 bytes, (256 bits).</description></item>
<item><description>The <see cref="M:CEX.Digest.SHA256.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> method wraps the <see cref="M:CEX.Digest.SHA256.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)"/> and DoFinal methods.</description>/&gt;</item>
<item><description>The <see cref="M:CEX.Digest.SHA256.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)"/> method resets the internal state.</description></item>
</list>

<description>Guiding Publications:</description>
<list type="number">
<item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">SHA-2 Specification</a>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Digest.SHA256.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\sha256.h" line="90">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Digest.SHA256.DigestSize" decl="false" source="c:\users\john\documents\github\cex\engine\sha256.h" line="95">
<summary>
Get: Size of returned digest in bytes
</summary>
</member>
<member name="M:CEX.Digest.SHA256.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\sha256.h" line="100">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.SHA256.Name" decl="false" source="c:\users\john\documents\github\cex\engine\sha256.h" line="105">
<summary>
Get: Digest name
</summary>
</member>
<member name="M:CEX.Digest.SHA256.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\sha256.h" line="112">
<summary>
Initialize the digest
</summary>
</member>
<member name="M:CEX.Digest.SHA256.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\sha256.h" line="127">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Digest.SHA256.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\sha256.h" line="137">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the input buffer is too short</exception>
</member>
<member name="M:CEX.Digest.SHA256.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\sha256.h" line="148">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.SHA256.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\sha256.h" line="156">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.SHA256.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\sha256.h" line="161">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the output buffer is too short</exception>
</member>
<member name="M:CEX.Digest.SHA256.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\sha256.h" line="173">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.SHA256.Update(System.Byte)" decl="true" source="c:\users\john\documents\github\cex\engine\sha256.h" line="178">
<summary>
Update the message digest with a single byte
</summary>

<param name="Input">Input byte</param>
</member>
<member name="T:CEX.Digest.SHA512" decl="false" source="c:\users\john\documents\github\cex\engine\sha512.h" line="41">
<summary>
SHA512: An implementation of the SHA-2 digest with a 512 bit digest return size
</summary> 

<example>
<description>Example using the ComputeHash method:</description>
<code>
SHA512 digest;
std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
// compute a hash
digest.ComputeHash(Input, hash);
</code>
</example>

<seealso cref="T:CEX.Digest.IDigest"/>
<seealso cref="T:CEX.Enumeration.Digests"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>Block size is 128 bytes, (1024 bits).</description></item>
<item><description>Digest size is 64 bytes, (512 bits).</description></item>
<item><description>The <see cref="M:CEX.Digest.SHA512.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> method wraps the <see cref="M:CEX.Digest.SHA512.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)"/> and DoFinal methods.</description>/&gt;</item>
<item><description>The <see cref="M:CEX.Digest.SHA512.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)"/> method resets the internal state.</description></item>
</list>

<description>Guiding Publications:</description>
<list type="number">
<item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">SHA-2 Specification</a>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Digest.SHA512.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\sha512.h" line="91">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Digest.SHA512.DigestSize" decl="false" source="c:\users\john\documents\github\cex\engine\sha512.h" line="96">
<summary>
Get: Size of returned digest in bytes
</summary>
</member>
<member name="M:CEX.Digest.SHA512.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\sha512.h" line="101">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.SHA512.Name" decl="false" source="c:\users\john\documents\github\cex\engine\sha512.h" line="106">
<summary>
Get: Digest name
</summary>
</member>
<member name="M:CEX.Digest.SHA512.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\sha512.h" line="113">
<summary>
Initialize the digest
</summary>
</member>
<member name="M:CEX.Digest.SHA512.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\sha512.h" line="137">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Digest.SHA512.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\sha512.h" line="147">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the input buffer is too short</exception>
</member>
<member name="M:CEX.Digest.SHA512.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\sha512.h" line="158">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.SHA512.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\sha512.h" line="166">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.SHA512.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\sha512.h" line="171">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the output buffer is too short</exception>
</member>
<member name="M:CEX.Digest.SHA512.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\sha512.h" line="183">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.SHA512.Update(System.Byte)" decl="true" source="c:\users\john\documents\github\cex\engine\sha512.h" line="188">
<summary>
Update the message digest with a single byte
</summary>

<param name="Input">Input byte</param>
</member>
<member name="F:Key" decl="false" source="c:\users\john\documents\github\cex\engine\ubitype.h" line="9">
<summary>
A key that turns Skein into a MAC or KDF function.
</summary>
</member>
<member name="F:Config" decl="false" source="c:\users\john\documents\github\cex\engine\ubitype.h" line="13">
<summary>
The configuration block.
</summary>
</member>
<member name="F:Personalization" decl="false" source="c:\users\john\documents\github\cex\engine\ubitype.h" line="17">
<summary>
A string that applications can use to create different functions for different uses.
</summary>
</member>
<member name="F:PublicKey" decl="false" source="c:\users\john\documents\github\cex\engine\ubitype.h" line="21">
<summary>
Used to hash the public key when hashing a message for signing.
</summary>
</member>
<member name="F:KeyIdentifier" decl="false" source="c:\users\john\documents\github\cex\engine\ubitype.h" line="25">
<summary>
Used for key derivation.
</summary>
</member>
<member name="F:Nonce" decl="false" source="c:\users\john\documents\github\cex\engine\ubitype.h" line="29">
<summary>
Nonce value for use in stream cipher mode and randomized hashing.
</summary>
</member>
<member name="F:Message" decl="false" source="c:\users\john\documents\github\cex\engine\ubitype.h" line="33">
<summary>
The normal message input of the hash function.
</summary>
</member>
<member name="F:Out" decl="false" source="c:\users\john\documents\github\cex\engine\ubitype.h" line="37">
<summary>
The output transform.
</summary>
</member>
<member name="T:UbiType" decl="false" source="c:\users\john\documents\github\cex\engine\ubitype.h" line="4">
<summary>
Specifies the Skein Ubi type
</summary>
</member>
<member name="F:Normal" decl="false" source="c:\users\john\documents\github\cex\engine\skeininitializationtype.h" line="9">
<summary>
Identical to the standard Skein initialization.
</summary>
</member>
<member name="F:ZeroedState" decl="false" source="c:\users\john\documents\github\cex\engine\skeininitializationtype.h" line="13">
<summary>
Creates the initial state with zeros instead of the configuration block, then initializes the hash.
This does not start a new UBI block type, and must be done manually.
</summary>
</member>
<member name="F:ChainedState" decl="false" source="c:\users\john\documents\github\cex\engine\skeininitializationtype.h" line="18">
<summary>
Leaves the initial state set to its previous value, which is then chained with subsequent block transforms.
This does not start a new UBI block type, and must be done manually.
</summary>
</member>
<member name="F:ChainedConfig" decl="false" source="c:\users\john\documents\github\cex\engine\skeininitializationtype.h" line="23">
<summary>
Creates the initial state by chaining the previous state value with the config block, then initializes the hash.
This starts a new UBI block type with the standard Payload type.
</summary>
</member>
<member name="T:SkeinInitializationType" decl="false" source="c:\users\john\documents\github\cex\engine\skeininitializationtype.h" line="4">
<summary>
Specifies the Skein initialization type
</summary>
</member>
<member name="T:UbiTweak" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="31">
<summary>
Part of Skein: the UBI Tweak structure.
</summary> 
</member>
<member name="M:UbiTweak.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="43">
<summary>
Initialize this class
</summary>
</member>
<member name="M:UbiTweak.Clear" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="52">
<summary>
Clear the teak value
</summary>
</member>
<member name="M:UbiTweak.GetBitsProcessed" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="60">
<summary>
Gets the number of bits processed so far, inclusive.
</summary>
</member>
<member name="M:UbiTweak.GetBlockType" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="68">
<summary>
Gets the current UBI block type.
</summary>
</member>
<member name="M:UbiTweak.GetIsFinalBlock" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="76">
<summary>
Gets the final block flag
</summary>
</member>
<member name="M:UbiTweak.GetIsFirstBlock" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="84">
<summary>
Gets the first block flag
</summary>
</member>
<member name="M:UbiTweak.GetTreeLevel" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="92">
<summary>
Gets the current tree level
</summary>
</member>
<member name="M:UbiTweak.GetTweak" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="100">
<summary>
Gets the tweak value array
</summary>
</member>
<member name="M:UbiTweak.SetBitsProcessed(System.UInt64!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="108">
<summary>
Sets the number of bits processed so far, inclusive
</summary>
</member>
<member name="M:UbiTweak.SetBlockType(&lt;unknown type&gt;!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="116">
<summary>
Sets the current UBI block type
</summary>
</member>
<member name="M:UbiTweak.SetIsFirstBlock(System.Boolean!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="124">
<summary>
Sets the first block flag
</summary>
</member>
<member name="M:UbiTweak.SetIsFinalBlock(System.UInt64!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="133">
<summary>
Sets the final block flag
</summary>
</member>
<member name="M:UbiTweak.SetTreeLevel(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="142">
<summary>
Sets the current tree level
</summary>
</member>
<member name="M:UbiTweak.SetTweak(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="154">
<summary>
Sets the tweak value array
</summary>
</member>
<member name="M:UbiTweak.StartNewBlockType(&lt;unknown type&gt;!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\github\cex\engine\skein.h" line="162">
<summary>
Starts a new UBI block type by setting BitsProcessed to zero, setting the first flag, and setting the block type
</summary>

<param name="Value">The UBI block type of the new block</param>
</member>
<member name="T:Threefish256" decl="false" source="c:\users\john\documents\github\cex\engine\threefish256.h" line="6">
<summary>
Part of Skein256: the Threefish cipher using a 256bit key size.
</summary> 
</member>
<member name="M:Threefish256.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\threefish256.h" line="22">
<summary>
Threefish with a 256 bit block
</summary>
</member>
<member name="M:Threefish256.Clear" decl="true" source="c:\users\john\documents\github\cex\engine\threefish256.h" line="34">
<summary>
Reset the state
</summary>
</member>
<member name="M:Threefish256.Encrypt(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\threefish256.h" line="39">
<summary>
Encrypt a block
</summary>

<param name="Input">Input array</param>
<param name="Output">Processed bytes</param>
</member>
<member name="M:Threefish256.SetKey(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\threefish256.h" line="47">
<summary>
Initialize the key
</summary>

<param name="Key">The cipher key</param>
</member>
<member name="M:Threefish256.SetTweak(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\threefish256.h" line="54">
<summary>
Initialize the tweak
</summary>

<param name="Tweak">The cipher tweak</param>
</member>
<member name="T:CEX.Digest.Skein256" decl="false" source="c:\users\john\documents\github\cex\engine\skein256.h" line="40">
<summary>
Skein256: An implementation of the Skein digest with a 256 bit digest return size
</summary>

<example>
<description>Example using the ComputeHash method:</description>
<code>
Skein256 digest;
std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
// compute a hash
digest.ComputeHash(Input, hash);
</code>
</example>

<seealso cref="T:CEX.Digest.IDigest"/>
<seealso cref="T:CEX.Enumeration.Digests"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>Block size is 32 bytes, (256 bits).</description></item>
<item><description>Digest size is 32 bytes, (256 bits).</description></item>
<item><description>The <see cref="M:CEX.Digest.Skein256.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> method wraps the <see cref="M:CEX.Digest.Skein256.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)"/> and DoFinal methods, and resets the internal state.</description>/&gt;</item>
<item><description>The <see cref="M:CEX.Digest.Skein256.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)"/> method does NOT reset the internal state; call <see cref="M:CEX.Digest.Skein256.Reset"/> to reinitialize.</description></item>
</list>

<description>Guiding Publications:</description>
<list type="number">
<item><description>Skein <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">The Skein digest</a>.</description></item>
<item><description>The Skein Hash Function Family <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">Skein V1.1</a>.</description></item>
<item><description>Skein <a href="http://www.skein-hash.info/sites/default/files/skein-proofs.pdf">Provable Security</a> Support for the Skein Hash Family.</description></item>
<item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3 Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition&gt;.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Digest.Skein256.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\skein256.h" line="99">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Digest.Skein256.DigestSize" decl="false" source="c:\users\john\documents\github\cex\engine\skein256.h" line="104">
<summary>
Get: Size of returned digest in bytes
</summary>
</member>
<member name="M:CEX.Digest.Skein256.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\skein256.h" line="109">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.Skein256.GetConfigString" decl="false" source="c:\users\john\documents\github\cex\engine\skein256.h" line="114">
<summary>
Get the pre-chain configuration string
</summary>
</member>
<member name="M:CEX.Digest.Skein256.GetConfigValue" decl="false" source="c:\users\john\documents\github\cex\engine\skein256.h" line="122">
<summary>
Get the post-chain configuration value
</summary>
</member>
<member name="M:CEX.Digest.Skein256.GetInitializationType" decl="false" source="c:\users\john\documents\github\cex\engine\skein256.h" line="130">
<summary>
Get the initialization type
</summary>
</member>
<member name="M:CEX.Digest.Skein256.GetStateSize" decl="false" source="c:\users\john\documents\github\cex\engine\skein256.h" line="138">
<summary>
Get the state size in bits
</summary>
</member>
<member name="M:CEX.Digest.Skein256.GetUbiParameters" decl="false" source="c:\users\john\documents\github\cex\engine\skein256.h" line="146">
<summary>
Ubi Tweak parameters
</summary>
</member>
<member name="M:CEX.Digest.Skein256.Name" decl="false" source="c:\users\john\documents\github\cex\engine\skein256.h" line="154">
<summary>
Get: Digest name
</summary>
</member>
<member name="M:CEX.Digest.Skein256.#ctor(&lt;unknown type&gt;)" decl="false" source="c:\users\john\documents\github\cex\engine\skein256.h" line="161">
<summary>
Initialize the digest
</summary>
</member>
<member name="M:CEX.Digest.Skein256.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\skein256.h" line="191">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Digest.Skein256.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="201">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the input buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Skein256.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="212">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.Skein256.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="220">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.Skein256.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="225">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the output buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Skein256.GenerateConfiguration(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;)" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="237">
<summary>
Generate a configuration using a state key
</summary>

<param name="InitialState">Twofish Cipher key</param>
</member>
<member name="M:CEX.Digest.Skein256.Initialize(&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="244">
<summary>
Used to re-initialize the digest state.
<para>Creates the initial state with zeros instead of the configuration block, then initializes the hash. 
This does not start a new UBI block type, and must be done manually.</para>
</summary>

<param name="InitializationType">Initialization parameters</param>
</member>
<member name="M:CEX.Digest.Skein256.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="253">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.Skein256.SetMaxTreeHeight(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="258">
<summary>
Set the tree height. Tree height must be zero or greater than 1.
</summary>

<param name="Height">Tree height</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if an invalid tree height is used</exception>
</member>
<member name="M:CEX.Digest.Skein256.SetSchema(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="267">
<summary>
Set the Schema. Schema must be 4 bytes.
</summary>

<param name="Schema">Schema Configuration string</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if an invalid schema is used</exception>
</member>
<member name="M:CEX.Digest.Skein256.SetTreeFanOutSize(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="276">
<summary>
Set the tree fan out size
</summary>

<param name="Size">Fan out size</param>
</member>
<member name="M:CEX.Digest.Skein256.SetTreeLeafSize(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="283">
<summary>
Set the tree leaf size
</summary>

<param name="Size">Leaf size</param>
</member>
<member name="M:CEX.Digest.Skein256.SetVersion(System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="290">
<summary>
Set the version string. Version must be between 0 and 3, inclusive.
</summary>

<param name="Version">Version string</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if an invalid version is used</exception>
</member>
<member name="M:CEX.Digest.Skein256.Update(System.Byte)" decl="true" source="c:\users\john\documents\github\cex\engine\skein256.h" line="299">
<summary>
Update the message digest with a single byte
</summary>

<param name="Input">Input byte</param>
</member>
<member name="T:Threefish512" decl="false" source="c:\users\john\documents\github\cex\engine\threefish512.h" line="6">
<summary>
Part of Skein512: the Threefish cipher using a 512bit key size.
</summary> 
</member>
<member name="M:Threefish512.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\threefish512.h" line="22">
<summary>
Threefish with a 512 bit block
</summary>
</member>
<member name="M:Threefish512.Clear" decl="true" source="c:\users\john\documents\github\cex\engine\threefish512.h" line="34">
<summary>
Reset the state
</summary>
</member>
<member name="M:Threefish512.Encrypt(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\threefish512.h" line="39">
<summary>
Encrypt a block
</summary>

<param name="Input">Input array</param>
<param name="Output">Processed bytes</param>
</member>
<member name="M:Threefish512.SetKey(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\threefish512.h" line="47">
<summary>
Initialize the key
</summary>

<param name="Key">The cipher key</param>
</member>
<member name="M:Threefish512.SetTweak(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\threefish512.h" line="54">
<summary>
Initialize the tweak
</summary>

<param name="Tweak">The cipher tweak</param>
</member>
<member name="T:CEX.Digest.Skein512" decl="false" source="c:\users\john\documents\github\cex\engine\skein512.h" line="40">
<summary>
Skein512: An implementation of the Skein digest with a 512 bit digest return size.
<para>SHA-3 finalist: The Skein digest</para>
</summary> 

<example>
<description>Example using the ComputeHash method:</description>
<code>
Skein512 digest;
std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
// compute a hash
digest.ComputeHash(Input, hash);
</code>
</example>

<seealso cref="T:CEX.Digest.IDigest"/>
<seealso cref="T:CEX.Enumeration.Digests"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>Block size is 64 bytes, (512 bits).</description></item>
<item><description>Digest size is 64 bytes, (512 bits).</description></item>
<item><description>The <see cref="M:CEX.Digest.Skein512.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> method wraps the <see cref="M:CEX.Digest.Skein512.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)"/> and DoFinal methods, and resets the internal state.</description>/&gt;</item>
<item><description>The <see cref="M:CEX.Digest.Skein512.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)"/> method does NOT reset the internal state; call <see cref="M:CEX.Digest.Skein512.Reset"/> to reinitialize.</description></item>
</list> 

<description>Guiding Publications:</description>
<list type="number">
<item><description>Skein <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">The Skein digest</a>.</description></item>
<item><description>The Skein Hash Function Family <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">Skein V1.1</a>.</description></item>
<item><description>Skein <a href="http://www.skein-hash.info/sites/default/files/skein-proofs.pdf">Provable Security</a> Support for the Skein Hash Family.</description></item>
<item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3 Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition&gt;.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Digest.Skein512.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\skein512.h" line="100">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Digest.Skein512.DigestSize" decl="false" source="c:\users\john\documents\github\cex\engine\skein512.h" line="105">
<summary>
Get: Size of returned digest in bytes
</summary>
</member>
<member name="M:CEX.Digest.Skein512.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\skein512.h" line="110">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.Skein512.GetConfigString" decl="false" source="c:\users\john\documents\github\cex\engine\skein512.h" line="115">
<summary>
Get the pre-chain configuration string
</summary>
</member>
<member name="M:CEX.Digest.Skein512.GetConfigValue" decl="false" source="c:\users\john\documents\github\cex\engine\skein512.h" line="123">
<summary>
Get the post-chain configuration value
</summary>
</member>
<member name="M:CEX.Digest.Skein512.GetInitializationType" decl="false" source="c:\users\john\documents\github\cex\engine\skein512.h" line="131">
<summary>
Get the initialization type
</summary>
</member>
<member name="M:CEX.Digest.Skein512.GetStateSize" decl="false" source="c:\users\john\documents\github\cex\engine\skein512.h" line="139">
<summary>
Get the state size in bits
</summary>
</member>
<member name="M:CEX.Digest.Skein512.GetUbiParameters" decl="false" source="c:\users\john\documents\github\cex\engine\skein512.h" line="147">
<summary>
Ubi Tweak parameters
</summary>
</member>
<member name="M:CEX.Digest.Skein512.Name" decl="false" source="c:\users\john\documents\github\cex\engine\skein512.h" line="157">
<summary>
Get: Digest name
</summary>
</member>
<member name="M:CEX.Digest.Skein512.#ctor(&lt;unknown type&gt;)" decl="false" source="c:\users\john\documents\github\cex\engine\skein512.h" line="162">
<summary>
Initialize the digest
</summary>
</member>
<member name="M:CEX.Digest.Skein512.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\skein512.h" line="192">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Digest.Skein512.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="202">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the input buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Skein512.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="213">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.Skein512.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="221">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.Skein512.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="226">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the output buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Skein512.GenerateConfiguration(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;)" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="238">
<summary>
Generate a configuration using a state key
</summary>

<param name="InitialState">Twofish Cipher key</param>
</member>
<member name="M:CEX.Digest.Skein512.Initialize(&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="245">
<summary>
Used to re-initialize the digest state.
<para>Creates the initial state with zeros instead of the configuration block, then initializes the hash. 
This does not start a new UBI block type, and must be done manually.</para>
</summary>

<param name="InitializationType">Initialization parameters</param>
</member>
<member name="M:CEX.Digest.Skein512.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="254">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.Skein512.SetMaxTreeHeight(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="259">
<summary>
Set the tree height. Tree height must be zero or greater than 1.
</summary>

<param name="Height">Tree height</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if an invalid tree height is used</exception>
</member>
<member name="M:CEX.Digest.Skein512.SetSchema(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="268">
<summary>
Set the Schema. Schema must be 4 bytes.
</summary>

<param name="Schema">Schema Configuration string</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if an invalid schema is used</exception>
</member>
<member name="M:CEX.Digest.Skein512.SetTreeFanOutSize(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="277">
<summary>
Set the tree fan out size
</summary>

<param name="Size">Fan out size</param>
</member>
<member name="M:CEX.Digest.Skein512.SetTreeLeafSize(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="284">
<summary>
Set the tree leaf size
</summary>

<param name="Size">Leaf size</param>
</member>
<member name="M:CEX.Digest.Skein512.SetVersion(System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="291">
<summary>
Set the version string. Version must be between 0 and 3, inclusive.
</summary>

<param name="Version">Version string</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if an invalid version is used</exception>
</member>
<member name="M:CEX.Digest.Skein512.Update(System.Byte)" decl="true" source="c:\users\john\documents\github\cex\engine\skein512.h" line="300">
<summary>
Update the message digest with a single byte
</summary>

<param name="Input">Input byte</param>
</member>
<member name="T:Threefish1024" decl="false" source="c:\users\john\documents\github\cex\engine\threefish1024.h" line="6">
<summary>
Part of Skein1024: the Threefish cipher using a 1024bit key size.
</summary> 
</member>
<member name="M:Threefish1024.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\threefish1024.h" line="22">
<summary>
Threefish with a 1024 bit block
</summary>
</member>
<member name="M:Threefish1024.Clear" decl="true" source="c:\users\john\documents\github\cex\engine\threefish1024.h" line="34">
<summary>
Reset the state
</summary>
</member>
<member name="M:Threefish1024.Encrypt(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\threefish1024.h" line="39">
<summary>
Encrypt a block
</summary>

<param name="Input">Input array</param>
<param name="Output">Processed bytes</param>
</member>
<member name="M:Threefish1024.SetKey(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\threefish1024.h" line="47">
<summary>
Initialize the key
</summary>

<param name="Key">The cipher key</param>
</member>
<member name="M:Threefish1024.SetTweak(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\threefish1024.h" line="54">
<summary>
Initialize the tweak
</summary>

<param name="Tweak">The cipher tweak</param>
</member>
<member name="T:CEX.Digest.Skein1024" decl="false" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="40">
<summary>
Skein1024: An implementation of the Skein digest with a 1024 bit digest return size.
<para>SHA-3 finalist: The Skein digest</para>
</summary> 

<example>
<description>Example using the ComputeHash method:</description>
<code>
Skein1024 digest;
std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
// compute a hash
digest.ComputeHash(Input, hash);
</code>
</example>

<seealso cref="T:CEX.Digest.IDigest"/>
<seealso cref="T:CEX.Enumeration.Digests"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>Block size is 128 bytes, (1024 bits).</description></item>
<item><description>Digest size is 128 bytes, (1024 bits).</description></item>
<item><description>The <see cref="M:CEX.Digest.Skein1024.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> method wraps the <see cref="M:CEX.Digest.Skein1024.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)"/> and DoFinal methods, and resets the internal state.</description>/&gt;</item>
<item><description>The <see cref="M:CEX.Digest.Skein1024.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)"/> method does NOT reset the internal state; call <see cref="M:CEX.Digest.Skein1024.Reset"/> to reinitialize.</description></item>
</list>

<description>Guiding Publications:</description>
<list type="number">
<item><description>Skein <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">The Skein digest</a>.</description></item>
<item><description>The Skein Hash Function Family <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">Skein V1.1</a>.</description></item>
<item><description>Skein <a href="http://www.skein-hash.info/sites/default/files/skein-proofs.pdf">Provable Security</a> Support for the Skein Hash Family.</description></item>
<item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3 Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition&gt;.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Digest.Skein1024.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="100">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.DigestSize" decl="false" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="105">
<summary>
Get: Size of returned digest in bytes
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="110">
<summary>
Get: The digests type enumeration member
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.Name" decl="false" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="115">
<summary>
Get: Digest name
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.GetConfigValue" decl="false" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="120">
<summary>
Get the post-chain configuration value
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.GetConfigString" decl="false" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="128">
<summary>
Get the pre-chain configuration string
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.GetInitializationType" decl="false" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="136">
<summary>
Get the initialization type
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.GetStateSize" decl="false" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="144">
<summary>
Get the state size in bits
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.GetUbiParameters" decl="false" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="152">
<summary>
Ubi Tweak parameters
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.#ctor(&lt;unknown type&gt;)" decl="false" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="162">
<summary>
Initialize the digest
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="192">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="202">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">The starting offset within the Input array</param>
<param name="Length">Amount of data to process in bytes</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the input buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Skein1024.ComputeHash(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="213">
<summary>
Get the Hash value
</summary>

<param name="Input">Input data</param>
<param name="Output">The hash output value array</param>
</member>
<member name="M:CEX.Digest.Skein1024.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="221">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="226">
<summary>
Do final processing and get the hash value
</summary>

<param name="Output">The Hash output value array</param>
<param name="OutOffset">The starting offset within the Output array</param>

<returns>Size of Hash value</returns>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if the output buffer is too short</exception>
</member>
<member name="M:CEX.Digest.Skein1024.GenerateConfiguration(std.vector&lt;System.UInt64,std.allocator&lt;System.UInt64&gt;&gt;)" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="238">
<summary>
Generate a configuration using a state key
</summary>

<param name="InitialState">Twofish Cipher key</param>
</member>
<member name="M:CEX.Digest.Skein1024.Initialize(&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="245">
<summary>
Used to re-initialize the digest state.
<para>Creates the initial state with zeros instead of the configuration block, then initializes the hash. 
This does not start a new UBI block type, and must be done manually.</para>
</summary>

<param name="InitializationType">Initialization parameters</param>
</member>
<member name="M:CEX.Digest.Skein1024.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="254">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Digest.Skein1024.SetMaxTreeHeight(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="259">
<summary>
Set the tree height. Tree height must be zero or greater than 1.
</summary>

<param name="Height">Tree height</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if an invalid tree height is used</exception>
</member>
<member name="M:CEX.Digest.Skein1024.SetSchema(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="268">
<summary>
Set the Schema. Schema must be 4 bytes.
</summary>

<param name="Schema">Schema Configuration string</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if an invalid schema is used</exception>
</member>
<member name="M:CEX.Digest.Skein1024.SetTreeFanOutSize(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="277">
<summary>
Set the tree fan out size
</summary>

<param name="Size">Fan out size</param>
</member>
<member name="M:CEX.Digest.Skein1024.SetTreeLeafSize(System.Byte!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="284">
<summary>
Set the tree leaf size
</summary>

<param name="Size">Leaf size</param>
</member>
<member name="M:CEX.Digest.Skein1024.SetVersion(System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="291">
<summary>
Set the version string. Version must be between 0 and 3, inclusive.
</summary>

<param name="Version">Version string</param>

<exception cref="T:CEX.Exception.CryptoDigestException">Thrown if an invalid version is used</exception>
</member>
<member name="M:CEX.Digest.Skein1024.Update(System.Byte)" decl="true" source="c:\users\john\documents\github\cex\engine\skein1024.h" line="300">
<summary>
Update the message digest with a single byte
</summary>

<param name="Input">Input byte</param>
</member>
</members>
</doc>