<?xml version="1.0"?><doc>
<members>
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
<member name="T:CEX.Utility.ParallelUtils" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\parallelutils.h" line="17">
<summary>
Parallel functions class
</summary> 
</member>
<member name="F:ChaCha" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamciphers.h" line="12">
<summary>
An implementation of the ChaCha Stream Cipher
</summary>
</member>
<member name="F:Salsa" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamciphers.h" line="16">
<summary>
A Salsa20 Stream Cipher
</summary>
</member>
<member name="T:CEX.Enumeration.StreamCiphers" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamciphers.h" line="7">
<summary>
Stream Ciphers
</summary>
</member>
<member name="T:CEX.Cipher.Symmetric.Stream.IStreamCipher" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="16">
<summary>
Stream Cipher Interface
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.#ctor" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="25">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="30">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.BlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="36">
<summary>
Get: Unit block size of internal cipher in bytes.
<para>Block size must be 16 or 32 bytes wide. 
Value set in class constructor.</para>
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="43">
<summary>
Get: The stream ciphers type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.IsInitialized" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="48">
<summary>
Get: Cipher is ready to transform data
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.IsParallel" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="53">
<summary>
Get/Set: Automatic processor parallelization
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.LegalKeySizes" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="58">
<summary>
Get: Unit block size of internal cipher in bytes.
<para>Block size must be 16 or 32 bytes wide. 
Value set in class constructor.</para>
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.LegalRounds" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="65">
<summary>
Get: Available diffusion round assignments
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="70">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.ParallelBlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="75">
<summary>
Get/Set: Parallel block size. Must be a multiple of <see cref="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.ParallelMinimumSize"/>.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.ParallelMaximumSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="80">
<summary>
Get: Maximum input size with parallel processing
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.ParallelMinimumSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="85">
<summary>
Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.ProcessorCount" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="90">
<remarks>
Get: Processor count
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.Rounds" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="95">
<summary>
Get: Number of rounds
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.VectorSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="100">
<summary>
Get: Initialization vector size
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.Destroy" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="107">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="112">
<summary>
Initialize the Cipher
</summary>

<param name="KeyParam">Cipher key container. The LegalKeySizes property contains valid sizes</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="119">
<summary>
Encrypt/Decrypt an array of bytes
</summary>

<param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
<param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="127">
<summary>
Encrypt/Decrypt an array of bytes with offset parameters.
<para><see cref="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\istreamcipher.h" line="138">
<summary>
Encrypt/Decrypt an array of bytes with offset and length parameters.
<para><see cref="M:CEX.Cipher.Symmetric.Stream.IStreamCipher.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
<param name="Length">Length of data to process</param>
</member>
<member name="T:CEX.Helper.StreamCipherFromName" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamcipherfromname.h" line="15">
<summary>
StreamCipherFromName: Get a Stream Cipher instance from it's enumeration name.
</summary>
</member>
<member name="M:CEX.Helper.StreamCipherFromName.GetInstance(&lt;unknown type&gt;,System.Int32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\streamcipherfromname.h" line="21">
<summary>
Get a stream cipher instance with specified initialization parameters
</summary>

<param name="EngineType">The stream cipher enumeration name</param>
<param name="RoundCount">The number of cipher rounds</param>

<returns>An initialized stream cipher</returns>

<exception cref="T:CEX.Exception.CryptoException">Thrown if the enumeration name is not supported</exception>
</member>
<member name="T:CEX.Cipher.Symmetric.Stream.ChaCha" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="45">
<summary>
ChaCha+: A parallelized ChaCha stream cipher implementation.
<para>A ChaCha cipher extended to use up to 30 rounds.</para>
</summary>

<example>
<description>Encrypt an array with ChaCha:</description>
<code>
KeyParams kp(Key, Iv);
ChaCha cipher(20);
// linear encrypt
cipher.Initialize(kp);
cipher.IsParallel() = false;
cipher.Transform(Input, Output);
</code>
</example>

<revisionHistory>
<revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
</revisionHistory>

<remarks>
<description><h4>Implementation Notes:</h4></description>
<list type="bullet">
<item><description>Valid Key sizes are 128 and 256 (16 and 32 bytes).</description></item>
<item><description>Block size is 64 bytes wide.</description></item>
<item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
</list>

<description><h4>Guiding Publications:</h4></description>
<list type="number">
<item><description>ChaCha20 <see href="http://cr.yp.to/chacha/chacha-20080128.pdf">Specification</see>.</description></item>
<item><description>Salsa20 <see href="http://cr.yp.to/snuffle/design.pdf">Design</see>.</description></item>
<item><description>Salsa20 <see href="http://cr.yp.to/snuffle/security.pdf">Security</see>.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.BlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="113">
<summary>
Get: Unit block size of internal cipher in bytes.
<para>Block size is 64 bytes wide.</para>
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.Counter" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="119">
<summary>
Get the current counter value
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.DistributionCode" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="124">
<summary>
Get/Set: Sets the Nonce value in the initialization parameters (Tau-Sigma).
<para>Must be set before <see cref="M:CEX.Cipher.Symmetric.Stream.ChaCha.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> is called.
Changing this code will create a unique distribution of the cipher.
Code must be 16 bytes in length and sufficiently asymmetric (no more than 2 repeating characters, at a distance of 2 intervals).</para>
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="132">
<summary>
Get: The stream ciphers type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.IsInitialized" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="137">
<summary>
Get: Cipher is ready to transform data
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.LegalKeySizes" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="142">
<summary>
Get: Available Encryption Key Sizes in bytes
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.LegalRounds" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="147">
<summary>
Get: Available diffusion round assignments
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.IsParallel" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="152">
<summary>
Get/Set: Automatic processor parallelization
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.ParallelBlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="157">
<summary>
Get/Set: Parallel block size. Must be a multiple of <see cref="M:CEX.Cipher.Symmetric.Stream.ChaCha.ParallelMinimumSize"/>.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.ParallelMaximumSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="162">
<summary>
Get: Maximum input size with parallel processing
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.ParallelMinimumSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="167">
<summary>
Get: The smallest parallel block size. 
<para>Parallel blocks must be a multiple of this size.</para>
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.ProcessorCount" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="173">
<remarks>
Get: Processor count
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="178">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.Rounds" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="183">
<summary>
Get: Number of rounds
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.VectorSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="188">
<summary>
Get: Initialization vector size
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.#ctor(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="195">
<summary>
Initialize the class
</summary>

<param name="Rounds">Number of diffusion rounds. The <see cref="M:CEX.Cipher.Symmetric.Stream.ChaCha.LegalRounds"/> property contains available sizes. Default is 20 rounds.</param>

<exception cref="T:CEX.Exception.CryptoSymmetricCipherException">Thrown if an invalid rounds count is chosen</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="223">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="233">
<summary>
Destroy of this class
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="238">
<summary>
Initialize the Cipher
</summary>

<param name="KeyParam">Cipher key container. 
<para>Uses the Key and IV fields of KeyParam. 
The <see cref="M:CEX.Cipher.Symmetric.Stream.ChaCha.LegalKeySizes"/> property contains valid Key sizes. 
IV must be 8 bytes in size.</para>
</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.Reset" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="249">
<summary>
Reset the primary internal counter
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="254">
<summary>
Encrypt/Decrypt an array of bytes.
<para><see cref="M:CEX.Cipher.Symmetric.Stream.ChaCha.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
<param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="263">
<summary>
Encrypt/Decrypt an array of bytes with offset parameters.
<para><see cref="M:CEX.Cipher.Symmetric.Stream.ChaCha.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.ChaCha.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\chacha.h" line="274">
<summary>
Encrypt/Decrypt an array of bytes with offset and length parameters.
<para><see cref="M:CEX.Cipher.Symmetric.Stream.ChaCha.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
<param name="Length">Number of bytes to process</param>
</member>
<member name="T:CEX.Cipher.Symmetric.Stream.Salsa20" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="45">
<summary>
Salsa20+: A parallelized Salsa20 stream cipher implementation.
<para>A Salsa20 cipher extended to use up to 30 rounds.</para>
</summary>

<example>
<description>Encrypt an array with Salsa20:</description>
<code>
KeyParams kp(key, iv);
Salsa20 cipher(20);
// linear encrypt
cipher.Initialize(kp);
cipher.IsParallel() = false;
cipher.Transform(Input, Output);
</code>
</example>

<revisionHistory>
<revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
</revisionHistory>

<remarks>
<description><h4>Implementation Notes:</h4></description>
<list type="bullet">
<item><description>Valid Key sizes are 128, 256 (16 and 32 bytes).</description></item>
<item><description>Block size is 64 bytes wide.</description></item>
<item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
<item><description>Parallel block size is 64,000 bytes by default; but is configurable.</description></item>
</list>

<description><h4>Guiding Publications:</h4></description>
<list type="number">
<item><description>Salsa20 <see href="http://www.ecrypt.eu.org/stream/salsa20pf.html">Specification</see>.</description></item>
<item><description>Salsa20 <see href="http://cr.yp.to/snuffle/design.pdf">Design</see>.</description></item>
<item><description>Salsa20 <see href="http://cr.yp.to/snuffle/security.pdf">Security</see>.</description></item>
</list>

</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.BlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="115">
<summary>
Get: Unit block size of internal cipher in bytes.
<para>Block size is 64 bytes wide.</para>
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.Counter" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="121">
<summary>
Get the current counter value
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.DistributionCode" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="126">
<summary>
Get/Set: Sets the Nonce value in the initialization parameters (Tau-Sigma).
<para>Must be set before <see cref="M:CEX.Cipher.Symmetric.Stream.Salsa20.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> is called.
Changing this code will create a unique distribution of the cipher.
Code must be 16 bytes in length and sufficiently asymmetric (no more than 2 repeating characters, at a distance of 2 intervals).</para>
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.Enumeral" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="134">
<summary>
Get: The stream ciphers type name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.IsInitialized" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="139">
<summary>
Get: Cipher is ready to transform data
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.IsParallel" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="144">
<summary>
Get/Set: Automatic processor parallelization
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.LegalKeySizes" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="149">
<summary>
Get: Available Encryption Key Sizes in bytes
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.LegalRounds" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="154">
<summary>
Get: Available diffusion round assignments
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.Name" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="159">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.ParallelBlockSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="164">
<summary>
Get/Set: Parallel block size. Must be a multiple of <see cref="M:CEX.Cipher.Symmetric.Stream.Salsa20.ParallelMinimumSize"/>.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.ParallelMaximumSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="169">
<summary>
Get: Maximum input size with parallel processing
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.ParallelMinimumSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="174">
<summary>
Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.ProcessorCount" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="179">
<remarks>
Get: Processor count
</remarks>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.Rounds" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="184">
<summary>
Get: Number of rounds
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.VectorSize" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="189">
<summary>
Get: Initialization vector size
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.#ctor(System.UInt32)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="196">
<summary>
Initialize the class
</summary>

<param name="Rounds">Number of diffusion rounds. The <see cref="M:CEX.Cipher.Symmetric.Stream.Salsa20.LegalRounds"/> property contains available sizes. Default is 20 rounds.</param>

<exception cref="T:CEX.Exception.CryptoSymmetricCipherException">Thrown if an invalid rounds count is chosen</exception>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="224">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.Destroy" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="234">
<summary>
Destroy of this class
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="239">
<summary>
Initialize the Cipher
</summary>

<param name="KeyParam">Cipher key container. 
<para>Uses the Key and IV fields of KeyParam. 
The <see cref="M:CEX.Cipher.Symmetric.Stream.Salsa20.LegalKeySizes"/> property contains valid Key sizes. 
IV must be 8 bytes in size.</para>
</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.Reset" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="250">
<summary>
Reset the primary internal counter
</summary>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="255">
<summary>
Encrypt/Decrypt an array of bytes.
<para><see cref="M:CEX.Cipher.Symmetric.Stream.Salsa20.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
<param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="264">
<summary>
Encrypt/Decrypt an array of bytes with offset parameters.
<para><see cref="M:CEX.Cipher.Symmetric.Stream.Salsa20.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
</member>
<member name="M:CEX.Cipher.Symmetric.Stream.Salsa20.Transform(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32!System.Runtime.CompilerServices.IsConst,System.UInt32!System.Runtime.CompilerServices.IsConst)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\salsa20.h" line="275">
<summary>
Encrypt/Decrypt an array of bytes with offset and length parameters.
<para><see cref="M:CEX.Cipher.Symmetric.Stream.Salsa20.Initialize(CEX.Common.KeyParams!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)"/> must be called before this method can be used.</para>
</summary>

<param name="Input">Input bytes to Transform</param>
<param name="InOffset">Offset in the Input array</param>
<param name="Output">Output product of Transform</param>
<param name="OutOffset">Offset in the Output array</param>
<param name="Length">Number of bytes to process</param>
</member>
</members>
</doc>