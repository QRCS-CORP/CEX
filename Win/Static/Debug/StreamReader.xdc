<?xml version="1.0"?><doc>
<members>
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
</members>
</doc>