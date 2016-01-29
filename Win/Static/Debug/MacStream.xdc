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
<!-- Discarding badly formed XML document comment for member 'T:CEX.Processing.MacStream'. -->
<member name="M:CEX.Processing.MacStream.#ctor(CEX.Mac.IMac*)" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\macstream.h" line="95">
<summary>
Initialize the class with an initialized Mac instance
</summary>

<param name="Mac">The initialized <see cref="T:CEX.Mac.IMac"/> instance</param>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if a null or uninitialized Mac is used</exception>
</member>
<member name="M:CEX.Processing.MacStream.Dispose" decl="false" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\macstream.h" line="116">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Processing.MacStream.ComputeMac(CEX.IO.IByteStream*)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\macstream.h" line="124">
<summary>
Process the entire length of the Input Stream
</summary>

<returns>The Mac Code</returns>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if ComputeHash is called before Initialize(), or if Size + Offset is longer than Input stream</exception>
</member>
<member name="M:CEX.Processing.MacStream.ComputeMac(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\visual studio 2015\projects\cryptography\cex++\engine\macstream.h" line="133">
<summary>
Process a length within the Input stream using an Offset
</summary>

<returns>The Mac Code</returns>
<param name="Input">The Input array to process</param>
<param name="InOffset">The Input array starting offset</param>
<param name="Length">The number of bytes to process</param>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if ComputeHash is called before Initialize(), or if Size + Offset is longer than Input stream</exception>
</member>
</members>
</doc>