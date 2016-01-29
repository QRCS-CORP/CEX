<?xml version="1.0"?><doc>
<members>
<member name="T:CEX.Exception.CryptoMacException" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptomacexception.h" line="8">
<summary>
Wraps exceptions thrown within Message Authentication Code operations
</summary>
</member>
<member name="M:CEX.Exception.CryptoMacException.Origin" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptomacexception.h" line="18">
<summary>
The origin of the exception in the format Class:Method
</summary>
</member>
<member name="M:CEX.Exception.CryptoMacException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptomacexception.h" line="27">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoMacException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\cryptomacexception.h" line="38">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:CMAC" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\macs.h" line="12">
<summary>
A Cipher based Message Authentication Code wrapper (CMAC)
</summary>
</member>
<member name="F:HMAC" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\macs.h" line="16">
<summary>
A Hash based Message Authentication Code wrapper (HMAC)
</summary>
</member>
<member name="F:VMAC" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\macs.h" line="20">
<summary>
A Variably Modified Permutation Composition based Message Authentication Code (VMPC-MAC)
</summary>
</member>
<member name="T:CEX.Enumeration.Macs" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\macs.h" line="7">
<summary>
Message Authentication Code Generators
</summary>
</member>
<member name="T:CEX.Mac.IMac" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="13">
<summary>
Message Authentication Code (MAC) Interface
</summary>
</member>
<member name="M:CEX.Mac.IMac.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="21">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Mac.IMac.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="26">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Mac.IMac.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="33">
<summary>
Get: The macs type name
</summary>
</member>
<member name="M:CEX.Mac.IMac.BlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="38">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Mac.IMac.MacSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="43">
<summary>
Get: Size of returned mac in bytes
</summary>
</member>
<member name="M:CEX.Mac.IMac.IsInitialized" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="48">
<summary>
Get: Mac is ready to digest data
</summary>
</member>
<member name="M:CEX.Mac.IMac.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="53">
<summary>
Get: Algorithm name
</summary>
</member>
<member name="M:CEX.Mac.IMac.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="60">
<summary>
Update the digest
</summary>

<param name="Input">Hash input data</param>
<param name="InOffset">Starting position with the Input array</param>
<param name="Length">Length of data to process</param>
</member>
<member name="M:CEX.Mac.IMac.ComputeMac(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="69">
<summary>
Get the MAC value
</summary>

<param name="Input">Input data</param>
<param name="Output">The output Mac code</param>
</member>
<member name="M:CEX.Mac.IMac.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="77">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Mac.IMac.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="82">
<summary>
Completes processing and returns the HMAC code
</summary>

<param name="Output">Output array that receives the hash code</param>
<param name="OutOffset">Offset within Output array</param>

<returns>The number of bytes processed</returns>
</member>
<member name="M:CEX.Mac.IMac.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="92">
<summary>
Initialize the MAC generator.
</summary>

<param name="KeyParam">The HMAC Key</param>
</member>
<member name="M:CEX.Mac.IMac.Reset" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="99">
<summary>
Reset and initialize the underlying digest
</summary>
</member>
<member name="M:CEX.Mac.IMac.Update(System.Byte)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\imac.h" line="104">
<summary>
Update the digest with 1 byte
</summary>

<param name="Input">Input byte</param>
</member>
<!-- Discarding badly formed XML document comment for member 'T:CEX.Mac.VMAC'. -->
<member name="M:CEX.Mac.VMAC.BlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="97">
<summary>
Get: The Digests internal blocksize in bytes
</summary>
</member>
<member name="M:CEX.Mac.VMAC.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="102">
<summary>
Get: The macs type name
</summary>
</member>
<member name="M:CEX.Mac.VMAC.MacSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="107">
<summary>
Get: Size of returned mac in bytes
</summary>
</member>
<member name="M:CEX.Mac.VMAC.IsInitialized" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="112">
<summary>
Get: Mac is ready to digest data
</summary>
</member>
<member name="M:CEX.Mac.VMAC.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="117">
<summary>
Get: Algorithm name
</summary>
</member>
<member name="M:CEX.Mac.VMAC.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="124">
<summary>
Initialize the VMAC class
</summary>
</member>
<member name="M:CEX.Mac.VMAC.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="146">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Mac.VMAC.BlockUpdate(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="156">
<summary>
Update the buffer
</summary>

<param name="Input">Input data</param>
<param name="InOffset">Offset within Input array</param>
<param name="Length">Amount of data to process in bytes</param>

<exception cref="T:CEX.Exception.CryptoMacException">Thrown if an invalid Input size is chosen</exception>
</member>
<member name="M:CEX.Mac.VMAC.ComputeMac(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="167">
<summary>
Get the Mac hash value
</summary>

<param name="Input">Input data</param>

<returns>Mac Hash value</returns>
</member>
<member name="M:CEX.Mac.VMAC.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="176">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Mac.VMAC.DoFinal(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="181">
<summary>
Process the last block of data
</summary>

<param name="Output">The hash value return</param>
<param name="OutOffset">The offset in the data</param>

<returns>The number of bytes processed</returns>

<exception cref="T:CEX.Exception.CryptoMacException">Thrown if Output array is too small</exception>
</member>
<member name="M:CEX.Mac.VMAC.Initialize(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="193">
<summary>
Initialize the VMPC MAC.
<para>Uses the Key and IV fields of the KeyParams class.</para>
</summary>

<param name="MacKey">A byte array containing the Key</param>
<param name="IV">A byte array containing the Initialization Vector</param>

<exception cref="T:CEX.Exception.CryptoMacException">Thrown if a null or invalid Key, or IV is used</exception>
</member>
<member name="M:CEX.Mac.VMAC.Reset" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="204">
<summary>
Reset the internal state
</summary>
</member>
<member name="M:CEX.Mac.VMAC.Update(System.Byte)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="209">
<summary>
Update the digest with a single byte
</summary>

<param name="Input">Input byte</param>
</member>
<member name="M:CEX.Mac.VMAC.InitKey(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\vmac.h" line="217">
<remarks>
Section 3.2, table 2 <see href="http://vmpcfunction.com/vmpc_mac.pdf">VMPC-MAC: 
A Stream Cipher Based Authenticated Encryption Scheme</see>
</remarks>
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
</members>
</doc>