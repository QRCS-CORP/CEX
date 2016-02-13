<?xml version="1.0"?><doc>
<members>
<member name="T:CEX.Exception.CryptoGeneratorException" decl="false" source="c:\users\john\documents\github\cex\engine\cryptogeneratorexception.h" line="8">
<summary>
Wraps exceptions thrown within Random Generator operations
</summary>
</member>
<member name="M:CEX.Exception.CryptoGeneratorException.Message" decl="false" source="c:\users\john\documents\github\cex\engine\cryptogeneratorexception.h" line="18">
<summary>
Get/Set: The message associated with the error
</summary>
</member>
<member name="M:CEX.Exception.CryptoGeneratorException.Origin" decl="false" source="c:\users\john\documents\github\cex\engine\cryptogeneratorexception.h" line="23">
<summary>
Get/Set: The origin of the exception in the format Class
</summary>
</member>
<member name="M:CEX.Exception.CryptoGeneratorException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptogeneratorexception.h" line="29">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoGeneratorException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptogeneratorexception.h" line="40">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:CTRDrbg" decl="false" source="c:\users\john\documents\github\cex\engine\generators.h" line="12">
<summary>
An implementation of a Encryption Counter based DRBG
</summary>
</member>
<member name="F:DGCDrbg" decl="false" source="c:\users\john\documents\github\cex\engine\generators.h" line="16">
<summary>
An implementation of a Digest Counter based DRBG
</summary>
</member>
<member name="F:HKDF" decl="false" source="c:\users\john\documents\github\cex\engine\generators.h" line="20">
<summary>
A Hash based Key Derivation Function HKDF
</summary>
</member>
<member name="F:KDF2Drbg" decl="false" source="c:\users\john\documents\github\cex\engine\generators.h" line="24">
<summary>
An implementation of a Hash based Key Derivation Function PBKDF2
</summary>
</member>
<member name="F:PBKDF2" decl="false" source="c:\users\john\documents\github\cex\engine\generators.h" line="28">
<summary>
An implementation of a Hash based Key Derivation PKCS#5 Version 2
</summary>
</member>
<member name="F:SP20Drbg" decl="false" source="c:\users\john\documents\github\cex\engine\generators.h" line="32">
<summary>
An implementation of a Salsa20 Counter based DRBG
</summary>
</member>
<member name="T:CEX.Enumeration.Generators" decl="false" source="c:\users\john\documents\github\cex\engine\generators.h" line="7">
<summary>
Random Generators
</summary>
</member>
<member name="T:CEX.Generator.IGenerator" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="12">
<summary>
Pseudo random Generator Interface
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="20">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="25">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="33">
<summary>
Get: The generators type name
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.IsInitialized" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="38">
<summary>
Get: Generator is ready to produce data
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.KeySize" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="43">
<summary>
<para>Minimum initialization key size in bytes; 
combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Name" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="49">
<summary>
Algorithm name
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Destroy" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="56">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Generator.IGenerator.Generate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="61">
<summary>
Generate a block of pseudo random bytes
</summary>

<param name="Output">Output array filled with random bytes</param>

<returns>Number of bytes generated</returns>
</member>
<member name="M:CEX.Generator.IGenerator.Generate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="70">
<summary>
Generate pseudo random bytes
</summary>

<param name="Output">Output array filled with random bytes</param>
<param name="OutOffset">The starting position within Output array</param>
<param name="Size">Number of bytes to generate</param>

<returns>Number of bytes generated</returns>
</member>
<member name="M:CEX.Generator.IGenerator.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="81">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
</member>
<member name="M:CEX.Generator.IGenerator.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="88">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
<param name="Ikm">Key material</param>
</member>
<member name="M:CEX.Generator.IGenerator.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="96">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
<param name="Ikm">Key material</param>
<param name="Nonce">Nonce value</param>
</member>
<member name="M:CEX.Generator.IGenerator.Update(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\igenerator.h" line="105">
<summary>
Update the Seed material
</summary>

<param name="Salt">Pseudo random seed material</param>
</member>
<member name="T:CEX.Generator.SP20Drbg" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="36">
<summary>
SP20Drbg: A parallelized Salsa20 deterministic random byte generator implementation
</summary>

<example>
<description>Generate an array of pseudo random bytes:</description>
<code>
SP20Drbg rnd(20);
// initialize
rnd.Initialize(Salt, [Ikm], [Nonce]);
// generate bytes
rnd.Generate(Output, [Offset], [Size]);
</code>
</example>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>Valid Key sizes are 128, 256 (16 and 32 bytes).</description></item>
<item><description>Block size is 64 bytes wide.</description></item>
<item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
<item><description>Parallel block size is 64,000 bytes by default; but is configurable.</description></item>
</list>

<description>Guiding Publications:</description>
<list type="number">
<item><description>Salsa20 <a href="http://www.ecrypt.eu.org/stream/salsa20pf.html">Specification</a>.</description></item>
<item><description>Salsa20 <a href="http://cr.yp.to/snuffle/design.pdf">Design</a>.</description></item>
<item><description>Salsa20 <a href="http://cr.yp.to/snuffle/security.pdf">Security</a>.</description></item>
</list>

</remarks>
</member>
<member name="M:CEX.Generator.SP20Drbg.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="102">
<summary>
Get: The generators type name
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.IsInitialized" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="107">
<summary>
Get: Generator is ready to produce data
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.IsParallel" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="112">
<summary>
Get/Set: Automatic processor parallelization
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.IV" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="117">
<summary>
Get: The current state of the initialization Vector
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.KeySize" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="122">
<summary>
<para>Minimum initialization key size in bytes; 
combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.LegalKeySizes" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="128">
<summary>
Get: Available Encryption Key Sizes in bytes
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.LegalRounds" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="133">
<summary>
Get: Available diffusion round assignments
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.Name" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="138">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.ParallelBlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="143">
<summary>
Get/Set: Parallel block size. Must be a multiple of <see cref="M:CEX.Generator.SP20Drbg.ParallelMinimumSize"/>.
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.ParallelMaximumSize" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="148">
<summary>
Get: Maximum input size with parallel processing
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.ParallelMinimumSize" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="153">
<summary>
Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.ProcessorCount" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="158">
<remarks>
Get: Processor count
</remarks>
</member>
<member name="M:CEX.Generator.SP20Drbg.VectorSize" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="163">
<summary>
Get: Initialization vector size
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.#ctor(System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="170">
<summary>
Initialize the SP20 generator
</summary>

<param name="Rounds">The number of transformation rounds</param>
</member>
<member name="M:CEX.Generator.SP20Drbg.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="192">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="202">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Generator.SP20Drbg.Generate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="207">
<summary>
Generate a block of pseudo random bytes
</summary>

<param name="Output">Output array filled with random bytes</param>

<returns>Number of bytes generated</returns>
</member>
<member name="M:CEX.Generator.SP20Drbg.Generate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="216">
<summary>
Generate pseudo random bytes
</summary>

<param name="Output">Output array filled with random bytes</param>
<param name="OutOffset">The starting position within Output array</param>
<param name="Size">Number of bytes to generate</param>

<returns>Number of bytes generated</returns>

<exception cref="T:CEX.Exception.CryptoGeneratorException">Thrown if the output buffer is too small</exception>
</member>
<member name="M:CEX.Generator.SP20Drbg.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="229">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value; must be either 24 or 40 bytes</param>

<exception cref="T:CEX.Exception.CryptoGeneratorException">Thrown if the Salt is too small</exception>
</member>
<member name="M:CEX.Generator.SP20Drbg.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="238">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
<param name="Ikm">Key material</param>
</member>
<member name="M:CEX.Generator.SP20Drbg.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="246">
<summary>
Initialize the generator
</summary>

<param name="Salt">Salt value</param>
<param name="Ikm">Key material</param>
<param name="Nonce">Nonce value</param>
</member>
<member name="M:CEX.Generator.SP20Drbg.Update(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\sp20drbg.h" line="255">
<summary>
Update the Salt material
</summary>

<param name="Salt">Pseudo random seed material</param>

<exception cref="T:CEX.Exception.CryptoGeneratorException">Thrown if the Salt value is too small</exception>
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
<member name="T:CEX.Utility.ParallelUtils" decl="false" source="c:\users\john\documents\github\cex\engine\parallelutils.h" line="17">
<summary>
Parallel functions class
</summary> 
</member>
<member name="M:CEX.Utility.ParallelUtils.ProcessorCount" decl="true" source="c:\users\john\documents\github\cex\engine\parallelutils.h" line="50">
<summary>
Get The number of processors available on the system
</summary>
</member>
<member name="M:CEX.Utility.ParallelUtils.ParallelFor(System.Int32,System.Int32,std.function&lt;(System.Int32)(System.Int32)&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\parallelutils.h" line="55">
<summary>
A multi platform Parallel For loop
</summary>

<param name="From">The starting position</param> 
<param name="To">The ending position</param>
<param name="F">The function delegate</param>
</member>
</members>
</doc>