<?xml version="1.0"?><doc>
<members>
<member name="F:B128" decl="false" source="c:\users\john\documents\github\cex\engine\blocksizes.h" line="13">
<summary>
128 bit block size
</summary>
</member>
<member name="F:B256" decl="false" source="c:\users\john\documents\github\cex\engine\blocksizes.h" line="17">
<summary>
256 bit block size
</summary>
</member>
<member name="F:B512" decl="false" source="c:\users\john\documents\github\cex\engine\blocksizes.h" line="21">
<summary>
512 bit block size
</summary>
</member>
<member name="F:B1024" decl="false" source="c:\users\john\documents\github\cex\engine\blocksizes.h" line="25">
<summary>
1024 bit block size
</summary>
</member>
<member name="T:CEX.Enumeration.BlockSizes" decl="false" source="c:\users\john\documents\github\cex\engine\blocksizes.h" line="7">
<summary>
<para>Block cipher sizes in bits. Can be cast as Block byte size integers, 
i.e. (int sz = BlockSizes.B512) is equal to 64.</para>
</summary>
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
<member name="F:V64" decl="false" source="c:\users\john\documents\github\cex\engine\ivsizes.h" line="13">
<summary>
64 bit IV
</summary>
</member>
<member name="F:V128" decl="false" source="c:\users\john\documents\github\cex\engine\ivsizes.h" line="17">
<summary>
128 bit IV
</summary>
</member>
<member name="F:V256" decl="false" source="c:\users\john\documents\github\cex\engine\ivsizes.h" line="21">
<summary>
256 bit IV
</summary>
</member>
<member name="T:CEX.Enumeration.IVSizes" decl="false" source="c:\users\john\documents\github\cex\engine\ivsizes.h" line="7">
<summary>
<para>IV Sizes in bits. Can be cast as IV byte size integers, 
i.e. (int sz = IVSizes.V128) is equal to 16.</para>
</summary>
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
<member name="F:None" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="12">
<summary>
Specify None if the input should not require padding (block aligned)
</summary>
</member>
<member name="F:ISO7816" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="16">
<summary>
ISO7816 Padding Mode
</summary>
</member>
<member name="F:PKCS7" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="20">
<summary>
PKCS7 Padding Mode
</summary>
</member>
<member name="F:TBC" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="24">
<summary>
Trailing Bit Complement Padding Mode
</summary>
</member>
<member name="F:X923" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="28">
<summary>
X923 Padding Mode
</summary>
</member>
<member name="T:CEX.Enumeration.PaddingModes" decl="false" source="c:\users\john\documents\github\cex\engine\paddingmodes.h" line="7">
<summary>
Block Cipher Padding Modes
</summary>
</member>
<member name="F:R8" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="13">
<summary>
8 Rounds: ChaCha
</summary>
</member>
<member name="F:R10" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="17">
<summary>
10 Rounds: ChaCha, RHX
</summary>
</member>
<member name="F:R12" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="21">
<summary>
12 Rounds: ChaCha, RHX
</summary>
</member>
<member name="F:R14" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="25">
<summary>
14 Rounds: ChaCha, RHX
</summary>
</member>
<member name="F:R16" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="29">
<summary>
16 Rounds: ChaCha, RHX, THX
</summary>
</member>
<member name="F:R18" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="33">
<summary>
18 Rounds: ChaCha, RHX, THX
</summary>
</member>
<member name="F:R20" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="37">
<summary>
20 Rounds: ChaCha, RHX, THX
</summary>
</member>
<member name="F:R22" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="41">
<summary>
22 Rounds: ChaCha, RHX, THX
</summary>
</member>
<member name="F:R24" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="45">
<summary>
24 Rounds: ChaCha, RHX, THX
</summary>
</member>
<member name="F:R26" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="49">
<summary>
26 Rounds: ChaCha, RHX, THX
</summary>
</member>
<member name="F:R28" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="53">
<summary>
28 Rounds: ChaCha, RHX, THX
</summary>
</member>
<member name="F:R30" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="57">
<summary>
30 Rounds: ChaCha, RHX, THX
</summary>
</member>
<member name="F:R32" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="61">
<summary>
32 Rounds: RHX, SHX, THX
</summary>
</member>
<member name="F:R34" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="65">
<summary>
34 Rounds, RHX
</summary>
</member>
<member name="F:R38" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="69">
<summary>
38 Rounds, RHX
</summary>
</member>
<member name="F:R40" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="73">
<summary>
40 Rounds: SHX
</summary>
</member>
<member name="F:R48" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="77">
<summary>
48 Rounds: SHX
</summary>
</member>
<member name="F:R56" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="81">
<summary>
56 Rounds: SHX
</summary>
</member>
<member name="F:R64" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="85">
<summary>
64 Rounds: SHX
</summary>
</member>
<member name="T:CEX.Enumeration.RoundCounts" decl="false" source="c:\users\john\documents\github\cex\engine\roundcounts.h" line="7">
<summary>
Rounds Count. Can be cast as round count integers, 
i.e. (int ct = RoundCounts.R12) is equal to 12.
</summary>
</member>
<member name="F:RHX" decl="false" source="c:\users\john\documents\github\cex\engine\symmetricengines.h" line="12">
<summary>
An implementation based on the Rijndael Block Cipher, using HKDF with a SHA512 HMAC for expanded key generation
</summary>
</member>
<member name="F:SHX" decl="false" source="c:\users\john\documents\github\cex\engine\symmetricengines.h" line="16">
<summary>
The Serpent Block Cipher Extended with an HKDF Key Schedule
</summary>
</member>
<member name="F:THX" decl="false" source="c:\users\john\documents\github\cex\engine\symmetricengines.h" line="20">
<summary>
A Twofish Block Cipher Extended with an HKDF Key Schedule
</summary>
</member>
<member name="F:ChaCha" decl="false" source="c:\users\john\documents\github\cex\engine\symmetricengines.h" line="24">
<summary>
An implementation of the ChaCha Stream Cipher
</summary>
</member>
<member name="F:Salsa" decl="false" source="c:\users\john\documents\github\cex\engine\symmetricengines.h" line="28">
<summary>
A Salsa20 Stream Cipher
</summary>
</member>
<member name="T:CEX.Enumeration.SymmetricEngines" decl="false" source="c:\users\john\documents\github\cex\engine\symmetricengines.h" line="7">
<summary>
Symmetric Encryption Ciphers
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
<member name="T:CEX.Common.CipherDescription" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="26">
<summary>
The CipherDescription structure.
<para>Used in conjunction with the CipherStream class.
Contains all the necessary settings required to recreate a cipher instance.</para>
</summary>

<example>
<description>Example of populating a <c>CipherDescription</c> structure:</description>
<code>
   CipherDescription dsc(
       Engines.RHX,             // cipher engine
       192,                     // key size in bytes
       IVSizes.V128,            // cipher iv size enum
       CipherModes.CTR,         // cipher mode enum
       PaddingModes.X923,       // cipher padding mode enum
       BlockSizes.B128,         // block size enum
       RoundCounts.R18,         // diffusion rounds enum
       Digests.Skein512,        // cipher kdf engine
       64,                      // mac size
       Digests.Keccak);         // mac digest
</code>
</example>

<seealso cref="T:CEX.Enumeration.BlockSizes"/>
<seealso cref="T:CEX.Enumeration.CipherModes"/>
<seealso cref="T:CEX.Enumeration.Digests"/>
<seealso cref="T:CEX.Enumeration.IVSizes"/>
<seealso cref="T:CEX.Enumeration.PaddingModes"/>
<seealso cref="T:CEX.Enumeration.RoundCounts"/>
<seealso cref="T:CEX.Enumeration.SymmetricEngines"/>
</member>
<member name="M:CEX.Common.CipherDescription.EngineType" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="95">
<summary>
The Cryptographic Engine type
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.KeySize" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="100">
<summary>
Get: The cipher Key Size
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.KeySize" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="105">
<summary>
Set: The cipher Key Size
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.IvSize" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="110">
<summary>
Size of the cipher Initialization Vector
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.CipherType" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="115">
<summary>
The type of Cipher Mode
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.PaddingType" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="120">
<summary>
The type of cipher Padding Mode
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.BlockSize" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="125">
<summary>
The cipher Block Size
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.RoundCount" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="130">
<summary>
The number of diffusion Rounds
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.KdfEngine" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="135">
<summary>
The Digest engine used to power the key schedule Key Derivation Function in HX and M series ciphers
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.MacSize" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="140">
<summary>
The size of the HMAC message authentication code; a zeroed parameter means authentication is not enabled with this key
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.MacEngine" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="145">
<summary>
The HMAC Digest engine used to authenticate a message file encrypted with this key
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="150">
<summary>
Default constructor
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.#ctor(&lt;unknown type&gt;,System.UInt32,&lt;unknown type&gt;,&lt;unknown type&gt;,&lt;unknown type&gt;,&lt;unknown type&gt;,&lt;unknown type&gt;,&lt;unknown type&gt;,System.UInt32,&lt;unknown type&gt;)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="167">
<summary>
CipherDescription constructor
</summary>

<param name="EngineType">The Cryptographic Engine type</param>
<param name="KeySize">The cipher Key Size in bytes</param>
<param name="IvSize">Size of the cipher Initialization Vector</param>
<param name="CipherType">The type of Cipher Mode</param>
<param name="PaddingType">The type of cipher Padding Mode</param>
<param name="BlockSize">The cipher Block Size</param>
<param name="RoundCount">The number of diffusion Rounds</param>
<param name="KdfEngine">The Digest engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
<param name="MacSize">The size of the HMAC message authentication code; a zeroed parameter means authentication is not enabled with this key</param>
<param name="MacEngine">The HMAC Digest engine used to authenticate a message file encrypted with this key</param>
</member>
<member name="M:CEX.Common.CipherDescription.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="196">
<summary>
Initialize the CipherDescription structure using a byte array
</summary>

<param name="DescriptionArray">The byte array containing the CipherDescription</param>
</member>
<member name="M:CEX.Common.CipherDescription.#ctor(CEX.IO.MemoryStream!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="218">
<summary>
Initialize the CipherDescription structure using a Stream
</summary>

<param name="DescriptionStream">The Stream containing the CipherDescription</param>
</member>
<member name="M:CEX.Common.CipherDescription.GetHeaderSize" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="239">
<summary>
Get the header Size in bytes
</summary>

<returns>Header size</returns>
</member>
<member name="M:CEX.Common.CipherDescription.Reset" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="249">
<summary>
Reset all struct members
</summary>
</member>
<member name="M:CEX.Common.CipherDescription.ToBytes" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="266">
<summary>
Convert the CipherDescription structure to a byte array
</summary>

<returns>The byte array containing the CipherDescription</returns>
</member>
<member name="M:CEX.Common.CipherDescription.ToStream" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="289">
<summary>
Convert the CipherDescription structure to a MemoryStream
</summary>

<returns>The MemoryStream containing the CipherDescription</returns>
</member>
<member name="M:CEX.Common.CipherDescription.GetHashCode" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="312">
<summary>
Get the hash code for this object
</summary>

<returns>Hash code</returns>
</member>
<member name="M:CEX.Common.CipherDescription.Equals(CEX.Common.CipherDescription*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherdescription.h" line="335">
<summary>
Compare this object instance with another
</summary>

<param name="Obj">Object to compare</param>

<returns>True if equal, otherwise false</returns>
</member>
<member name="T:CEX.Exception.CryptoRandomException" decl="false" source="c:\users\john\documents\github\cex\engine\cryptorandomexception.h" line="8">
<summary>
Wraps exceptions thrown within Pseudo Random Number Generator operations
</summary>
</member>
<member name="M:CEX.Exception.CryptoRandomException.Message" decl="false" source="c:\users\john\documents\github\cex\engine\cryptorandomexception.h" line="18">
<summary>
Get/Set: The message associated with the error
</summary>
</member>
<member name="M:CEX.Exception.CryptoRandomException.Origin" decl="false" source="c:\users\john\documents\github\cex\engine\cryptorandomexception.h" line="23">
<summary>
Get/Set: The origin of the exception in the format Class
</summary>
</member>
<member name="M:CEX.Exception.CryptoRandomException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptorandomexception.h" line="29">
<summary>
Exception constructor
</summary>

<param name="Message">A custom message or error data</param>
</member>
<member name="M:CEX.Exception.CryptoRandomException.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cryptorandomexception.h" line="40">
<summary>
Exception constructor
</summary>

<param name="Origin">The origin of the exception</param>
<param name="Message">A custom message or error data</param>
</member>
<member name="F:CSPPrng" decl="false" source="c:\users\john\documents\github\cex\engine\prngs.h" line="12">
<summary>
 A Secure PRNG using RNGCryptoServiceProvider
</summary>
</member>
<member name="F:CTRPrng" decl="false" source="c:\users\john\documents\github\cex\engine\prngs.h" line="16">
<summary>
A Symmetric Cipher Counter mode random number generator
</summary>
</member>
<member name="F:DGCPrng" decl="false" source="c:\users\john\documents\github\cex\engine\prngs.h" line="20">
<summary>
A Digest Counter mode random number generator
</summary>
</member>
<member name="F:PPBPrng" decl="false" source="c:\users\john\documents\github\cex\engine\prngs.h" line="24">
<summary>
An implementation of a passphrase based PKCS#5 random number generator
</summary>
</member>
<member name="F:SP20Prng" decl="false" source="c:\users\john\documents\github\cex\engine\prngs.h" line="28">
<summary>
An implementation of a Salsa20 Counter based Prng
</summary>
</member>
<member name="T:CEX.Enumeration.Prngs" decl="false" source="c:\users\john\documents\github\cex\engine\prngs.h" line="7">
<summary>
Pseudo Random Generators
</summary>
</member>
<member name="T:CEX.Prng.IRandom" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="12">
<summary>
Psuedo Random Number Generator interface
</summary>
</member>
<member name="M:CEX.Prng.IRandom.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="20">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.Prng.IRandom.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="25">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Prng.IRandom.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="32">
<summary>
Get: The prngs type name
</summary>
</member>
<member name="M:CEX.Prng.IRandom.Name" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="37">
<summary>
Get: Algorithm name
</summary>
</member>
<member name="M:CEX.Prng.IRandom.Destroy" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="44">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Prng.IRandom.GetBytes(System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="49">
<summary>
Return an array filled with pseudo random bytes
</summary>

<param name="Size">Size of requested byte array</param>

<returns>Random byte array</returns>
</member>
<member name="M:CEX.Prng.IRandom.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="58">
<summary>
Fill an array with pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Prng.IRandom.Next" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="65">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.IRandom.Next(System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="72">
<summary>
Get an pseudo random unsigned 32bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.IRandom.Next(System.UInt32,System.UInt32)" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="81">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random UInt32</returns>
</member>
<member name="M:CEX.Prng.IRandom.NextLong" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="91">
<summary>
Get a pseudo random unsigned 64bit integer
</summary>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.IRandom.NextLong(System.UInt64)" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="98">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.IRandom.NextLong(System.UInt64,System.UInt64)" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="107">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random UInt64</returns>
</member>
<member name="M:CEX.Prng.IRandom.Reset" decl="false" source="c:\users\john\documents\github\cex\engine\irandom.h" line="117">
<summary>
Reset the generator instance
</summary>
</member>
<member name="F:CSPRsg" decl="false" source="c:\users\john\documents\github\cex\engine\seedgenerators.h" line="12">
<summary>
A Secure Seed Generator using RNGCryptoServiceProvider
</summary>
</member>
<member name="F:ISCRsg" decl="false" source="c:\users\john\documents\github\cex\engine\seedgenerators.h" line="16">
<summary>
A Secure Seed Generator using the entropy pool and an ISAAC generator
</summary>
</member>
<member name="F:XSPRsg" decl="false" source="c:\users\john\documents\github\cex\engine\seedgenerators.h" line="20">
<summary>
A (fast but less secure) Seed Generator using the entropy pool and an XorShift+ generator
</summary>
</member>
<member name="T:CEX.Enumeration.SeedGenerators" decl="false" source="c:\users\john\documents\github\cex\engine\seedgenerators.h" line="7">
<summary>
Seed Generators
</summary>
</member>
<member name="T:CEX.Seed.ISeed" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="12">
<summary>
ISeed: Pseudo random seed generator interface
</summary>
</member>
<member name="M:CEX.Seed.ISeed.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="20">
<summary>
CTor: Initialize this class
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="25">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="32">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Name" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="37">
<summary>
Get: Algorithm name
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Destroy" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="44">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.ISeed.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="49">
<summary>
Get the pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Seed.ISeed.GetBytes(System.Int32)" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="56">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.ISeed.Next" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="65">
<summary>
Returns the next pseudo random 32bit integer
</summary>
</member>
<member name="M:CEX.Seed.ISeed.Reset" decl="false" source="c:\users\john\documents\github\cex\engine\iseed.h" line="70">
<summary>
Reset the internal state
</summary>
</member>
<member name="T:CEX.Seed.CSPRsg" decl="false" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="16">
<summary>
CSPRsg: An implementation of a Cryptographically Secure seed generator using the RNGCryptoServiceProvider class
</summary>

<example>
<description>Example of getting a seed value:</description>
<code>
CSPRsg gen;
gen.GetSeed(Output);
</code>
</example>

<remarks>
<description>Guiding Publications::</description>
<list type="number">
<item><description>Microsoft <a href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx">RNGCryptoServiceProvider</a>: class documentation.</description></item>
<item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
<item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
<item><description>RFC <a href="http://www.ietf.org/rfc/rfc4086.txt">4086</a>: Randomness Requirements for Security.</description></item>
</list> 
</remarks>
</member>
<member name="M:CEX.Seed.CSPRsg.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="47">
<summary>
Get: The seed generators type name
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Name" decl="false" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="52">
<summary>
Get: Cipher name
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="59">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="67">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="77">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="82">
<summary>
Fill the buffer with random bytes
</summary>

<param name="Output">The array to fill</param>
</member>
<member name="M:CEX.Seed.CSPRsg.GetBytes(System.Int32)" decl="true" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="89">
<summary>
Get a pseudo random seed byte array
</summary>

<param name="Size">The size of the expected seed returned</param>

<returns>A pseudo random seed</returns>
</member>
<member name="M:CEX.Seed.CSPRsg.Next" decl="true" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="98">
<summary>
Returns the next pseudo random 32bit integer
</summary>
</member>
<member name="M:CEX.Seed.CSPRsg.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\csprsg.h" line="103">
<summary>
Reset the internal state
</summary>
</member>
<member name="T:CEX.Prng.CSPPrng" decl="false" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="38">
<summary>
An implementation of a Cryptographically Secure PRNG using the the operating system random provider
</summary>

<example>
<description>Example of generating a pseudo random integer:</description>
<code>
CSPPrng rnd();
int x = rnd.Next();
</code>
</example>

<remarks>
<description>Guiding Publications::</description>
<list type="number">
<item><description>Microsoft <a href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx">RNGCryptoServiceProvider</a>: class documentation.</description></item>
<item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
<item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
<item><description>RFC <a href="http://www.ietf.org/rfc/rfc4086.txt">4086</a>: Randomness Requirements for Security.</description></item>
</list> 
</remarks>
</member>
<member name="M:CEX.Prng.CSPPrng.Enumeral" decl="false" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="69">
<summary>
Get: The prngs type name
</summary>
</member>
<member name="M:CEX.Prng.CSPPrng.Name" decl="false" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="74">
<summary>
Get: Digest name
</summary>
</member>
<member name="M:CEX.Prng.CSPPrng.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="81">
<summary>
Initialize this class
</summary>
</member>
<member name="M:CEX.Prng.CSPPrng.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="91">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.Prng.CSPPrng.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="101">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Prng.CSPPrng.GetBytes(System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="106">
<summary>
Return an array filled with pseudo random bytes
</summary>

<param name="Size">Size of requested byte array</param>

<returns>Random byte array</returns>
</member>
<member name="M:CEX.Prng.CSPPrng.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="115">
<summary>
Fill an array with pseudo random bytes
</summary>

<param name="Output">Output array</param>
</member>
<member name="M:CEX.Prng.CSPPrng.Next" decl="true" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="122">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<returns>Random 32bit integer</returns>
</member>
<member name="M:CEX.Prng.CSPPrng.Next(System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="129">
<summary>
Get an pseudo random unsigned 32bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random 32bit integer</returns>
</member>
<member name="M:CEX.Prng.CSPPrng.Next(System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="138">
<summary>
Get a pseudo random unsigned 32bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random 32bit integer</returns>
</member>
<member name="M:CEX.Prng.CSPPrng.NextLong" decl="true" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="148">
<summary>
Get a pseudo random unsigned 64bit integer
</summary>

<returns>Random 64bit integer</returns>
</member>
<member name="M:CEX.Prng.CSPPrng.NextLong(System.UInt64)" decl="true" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="155">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Maximum">Maximum value</param>

<returns>Random 64bit integer</returns>
</member>
<member name="M:CEX.Prng.CSPPrng.NextLong(System.UInt64,System.UInt64)" decl="true" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="164">
<summary>
Get a ranged pseudo random unsigned 64bit integer
</summary>

<param name="Minimum">Minimum value</param>
<param name="Maximum">Maximum value</param>

<returns>Random 64bit integer</returns>
</member>
<member name="M:CEX.Prng.CSPPrng.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\cspprng.h" line="174">
<summary>
Reset the generator instance
</summary>
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
<member name="T:CEX.Processing.Structure.CipherKey" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="14">
<summary>
The CipherKey structure.
<para>Used in conjunction with the CipherStream class. 
This structure is used as the header for a single use key and vector set.</para>
</summary>

<example>
<description>Example of populating a CipherKey structure:</description>
<code>
CipherKey ck = new CipherKey(description);
</code>
</example>

<seealso cref="T:CEX.Common.CipherDescription"/>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.Description" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="44">
<summary>
The CipherDescription structure containing a complete description of the cipher instance
</summary>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.KeyId" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="49">
<summary>
The unique 16 byte ID field used to identify this key. A null value auto generates this field
</summary>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.ExtensionKey" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="54">
<summary>
An array of random bytes used to encrypt a message file extension. A null value auto generates this field
</summary>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.#ctor" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="59">
<summary>
Default constructor
</summary>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.#ctor(CEX.Common.CipherDescription*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="70">
<summary>
CipherKey structure constructor.
<para>KeyID and ExtRandom values must each be 16 bytes in length.
If they are not specified they will be populated automatically.</para>
</summary>

<param name="Description">The CipherDescriptionstructure containing a complete description of the cipher instance</param>
<param name="KeyId">The unique 16 byte ID field used to identify this key. A null value auto generates this field</param>
<param name="ExtensionKey">An array of random bytes used to encrypt a message file extension. A null value auto generates this field</param>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if either the KeyId or ExtensionKey fields are null or invalid</exception>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.#ctor(CEX.IO.MemoryStream*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="119">
<summary>
Initialize the CipherKey structure using a Stream
</summary>

<param name="KeyStream">The Stream containing the CipherKey</param>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.#ctor(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="135">
<summary>
Initialize the CipherKey structure using a byte array
</summary>

<param name="KeyArray">The byte array containing the CipherKey</param>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.Reset" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="152">
<summary>
Reset all members of the CipherKey structure, including the CipherDescription
</summary>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.ToBytes" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="164">
<summary>
Convert the CipherKey structure as a byte array
</summary>

<returns>The byte array containing the CipherKey</returns>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.ToStream" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="179">
<summary>
Convert the CipherKey structure to a MemoryStream
</summary>

<returns>The MemoryStream containing the CipherKey</returns>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.GetHeaderSize" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="194">
<summary>
Get the header Size in bytes
</summary>

<returns>Header size</returns>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.GetCipherDescription(CEX.IO.MemoryStream*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="204">
<summary>
Get the cipher description header
</summary>

<param name="KeyStream">The stream containing a key package</param>

<returns>CipherDescription structure</returns>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.GetExtensionKey(CEX.IO.MemoryStream*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="217">
<summary>
Get the extension key (16 bytes)
</summary>

<param name="KeyStream">The stream containing the cipher key</param>

<returns>The file extension key</returns>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.GetKeyId(CEX.IO.MemoryStream*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="230">
<summary>
Get the key id (16 bytes)
</summary>

<param name="KeyStream">The stream containing a cipher key</param>

<returns>The file extension key</returns>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.SetCipherDescription(CEX.IO.MemoryStream*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,CEX.Common.CipherDescription*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="243">
<summary>
Set the CipherDescription structure
</summary>

<param name="KeyStream">The stream containing a key package</param>
<param name="Description">The CipherDescription structure</param>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.SetExtensionKey(CEX.IO.MemoryStream*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="255">
<summary>
Set the ExtensionKey
</summary>

<param name="KeyStream">The stream containing a cipher key</param>
<param name="ExtensionKey">Array of 16 bytes containing the ExtensionKey</param>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.SetKeyId(CEX.IO.MemoryStream*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="267">
<summary>
Set the Key Id
</summary>

<param name="KeyStream">The stream containing a cipher key</param>
<param name="KeyId">Array of 16 bytes containing the key id</param>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.GetHashCode" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="279">
<summary>
Get the hash code for this object
</summary>

<returns>Hash code</returns>
</member>
<member name="M:CEX.Processing.Structure.CipherKey.Equals(CEX.Processing.Structure.CipherKey*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\cipherkey.h" line="295">
<summary>
Compare this object instance with another
</summary>

<param name="Obj">Object to compare</param>

<returns>True if equal, otherwise false</returns>
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
<member name="T:CEX.Processing.Factory.KeyFactory" decl="false" source="c:\users\john\documents\github\cex\engine\keyfactory.h" line="12">
<summary>
KeyFactory: Used to create or extract a CipherKey file.

<list type="bullet">
<item><description>The Constructor requires a pointer to a MemoryStream for reading or writing; using Create() objects are written to the stream, with Extract() objects are read from the stream.</description></item>
<item><description>The Create(CipherDescription, KeyParams) method requires a populated CipherDescription and KeyParams class.</description></item>
<item><description>The Create(CipherDescription, SeedGenerators, Digests) method will auto-generate keying material.</description></item>
<item><description>The Extract() method retrieves a populated cipher key (CipherKey), and key material (KeyParams), from the key stream.</description></item>
</list>
</summary>

<example>
<description>Example using the Create() and Extract methods:</description>
<code>
KeyGenerator kg;
KeyParams kp = *kg.GetKeyParams(192, 16, 64);
// out-bound funcs use pointer
MemoryStream* m = new MemoryStream;
CEX::Processing::KeyFactory kf(m);

CipherDescription ds(
	SymmetricEngines::RHX,
	192,
	IVSizes::V128,
	CipherModes::CTR,
	PaddingModes::PKCS7,
	BlockSizes::B128,
	RoundCounts::R22,
	Digests::Skein512,
	64,
	Digests::SHA512);

kf.Create(ds, kp);
KeyParams kp2;
m-&gt;Seek(0, CEX::IO::SeekOrigin::Begin);
CEX::Processing::CipherKey ck;
kf.Extract(ck, kp2);

if (!ds.Equals(ck.Description()))
	throw;
if (!kp.Equals(kp2))
	throw;

delete m;
</code>
</example>

<seealso cref="T:CEX.Processing.Structure.CipherKey"/>
<seealso cref="T:CEX.Common.CipherDescription"/>
<seealso cref="T:CEX.Enumeration.Prngs"/>
<seealso cref="T:CEX.Enumeration.Digests"/>
<seealso cref="T:CEX.Common.KeyParams"/>
</member>
<member name="M:CEX.Processing.Factory.KeyFactory.#ctor(CEX.IO.MemoryStream*)" decl="false" source="c:\users\john\documents\github\cex\engine\keyfactory.h" line="74">
<summary>
Initialize this class with a memory stream; key will be written to the stream
</summary>

<param name="KeyStream">The fully qualified path to the key file to be read or created</param>
</member>
<member name="M:CEX.Processing.Factory.KeyFactory.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\keyfactory.h" line="86">
<summary>
Finalizer: ensure resources are destroyed
</summary>
</member>
<member name="M:CEX.Processing.Factory.KeyFactory.Create(CEX.Common.CipherDescription*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,&lt;unknown type&gt;,&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\github\cex\engine\keyfactory.h" line="93">
<summary>
Create a single use key file using automatic key material generation.
<para>The Key, and optional IV and IKM are generated automatically using the cipher description contained in the CipherDescription.
This overload creates keying material using the seed and digest engines specified with the KeyGenerator class</para>
</summary>

<param name="Description">The Cipher Description containing the cipher implementation details</param>
<param name="SeedEngine">The Random Generator used to create the stage I seed material during key generation.</param>
<param name="HashEngine">The Digest Engine used in the stage II phase of key generation.</param>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if a KeyParams member is null, but specified in the Header</exception>
</member>
<member name="M:CEX.Processing.Factory.KeyFactory.Create(CEX.Common.CipherDescription*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,CEX.Common.KeyParams*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\keyfactory.h" line="106">
<summary>
Create a single use key file using a KeyParams containing the key material, and a CipherDescription containing the cipher implementation details
</summary>

<param name="Description">The Cipher Description containing the cipher details</param>
<param name="KeyParam">An initialized and populated key material container</param>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if a KeyParams member is null, but specified in the Header or a Header parameter does not match a KeyParams value</exception>
</member>
<member name="M:CEX.Processing.Factory.KeyFactory.Create(CEX.Common.KeyParams*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,&lt;unknown type&gt;,System.Int32,&lt;unknown type&gt;,&lt;unknown type&gt;,&lt;unknown type&gt;,&lt;unknown type&gt;,&lt;unknown type&gt;,&lt;unknown type&gt;,System.Int32,&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\github\cex\engine\keyfactory.h" line="116">
<summary>
Create a single use Key file using a manual description of the cipher parameters.
</summary>

<param name="KeyParam">An initialized and populated key material container</param>
<param name="EngineType">The Cryptographic Engine type</param>
<param name="KeySize">The cipher Key Size in bytes</param>
<param name="IvSize">Size of the cipher Initialization Vector</param>
<param name="CipherType">The type of Cipher Mode</param>
<param name="PaddingType">The type of cipher Padding Mode</param>
<param name="BlockSize">The cipher Block Size</param>
<param name="Rounds">The number of diffusion Rounds</param>
<param name="KdfEngine">The Digest engine used to power the key schedule Key Derivation Function in HX ciphers</param>
<param name="MacSize">The size of the HMAC message authentication code; a zeroed parameter means authentication is not enabled with this key</param>
<param name="MacEngine">The HMAC Digest engine used to authenticate a message file encrypted with this key</param>
</member>
<member name="M:CEX.Processing.Factory.KeyFactory.Extract(CEX.Processing.Structure.CipherKey*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,CEX.Common.KeyParams*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\keyfactory.h" line="135">
<summary>
Extract a KeyParams and CipherKey
</summary>

<param name="KeyHeader">The CipherKey that receives the cipher description, key id, and extension key</param>
<param name="KeyParam">The KeyParams container that receives the key material from the file</param>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if the key file could not be found or a Header parameter does not match the keystream length</exception>
</member>
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
<member name="T:CEX.Common.KeyGenerator" decl="false" source="c:\users\john\documents\github\cex\engine\keygenerator.h" line="12">
<summary>
A helper class for generating cryptographically strong keying material.
<para>Generates an array or a populated KeyParams class, using a definable Digest(Prng()) dual stage generator.
The first stage of the generator gets seed material from the Prng provider, the second hashes the seed and adds the result to the state array.
A counter array can be prepended to the seed array, sized between 4 and 32 bytes. 
The counter is incremented and prepended to the seed value before each hash call. 
If the Counter size parameter is <c>0</c> in the constructor, or the default constructor is used, 
the counter is provided by the default random provider.</para>
</summary>

<example>
<description>Create an array of pseudo random keying material:</description>
<code>
KeyGenerator* gen = new KeyGenerator([Prng], [Digest], [Counter Size]))
// generate pseudo random bytes
std:vector&lt;byte&gt; prnd = gen.Generate(Size);
</code>
</example>

<seealso cref="T:CEX.Digest.IDigest"/>
<seealso cref="T:CEX.Enumeration.Digests"/>
<seealso cref="N:CEX.Seed"/>
<seealso cref="T:CEX.Seed.ISeed"/>
<seealso cref="T:CEX.Enumeration.SeedGenerators"/>

<remarks>
<description>Implementation Notes:</description>
<list type="bullet">
<item><description>SHA-2 Generates key material using a two stage Hmac_k(Prng()) process.</description></item>
<item><description>Blake, Keccak, and Skein also use a two stage generation method; Hash(Prng()).</description></item>
<item><description>Seed provider can be any of the <see cref="T:CEX.Enumeration.SeedGenerators"/> generators.</description></item>
<item><description>Hash can be any of the <see cref="T:CEX.Enumeration.Digests"/> digests.</description></item>
<item><description>Default Prng is CSPPrng, default digest is SHA512.</description></item>
<item><description>Resources are disposed of automatically.</description></item>
</list>
</remarks>
</member>
<member name="M:CEX.Common.KeyGenerator.#ctor(&lt;unknown type&gt;,&lt;unknown type&gt;)" decl="false" source="c:\users\john\documents\github\cex\engine\keygenerator.h" line="62">
<summary>
Initialize this class.
<para>Initializes the class with default generators; SHA-2 512, and CSPPrng.
The digest counter mechanism is set to <c>O</c> (disabled) by default.</para>
</summary>

<param name="SeedType">The Seed Generators that supplies the seed material to the hash function</param>
<param name="DigestType">The Digest type used to post-process the pseudo random seed material</param>
</member>
<member name="M:CEX.Common.KeyGenerator.#ctor(&lt;unknown type&gt;!System.Runtime.CompilerServices.IsConst,&lt;unknown type&gt;!System.Runtime.CompilerServices.IsConst,std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="false" source="c:\users\john\documents\github\cex\engine\keygenerator.h" line="82">
<summary>
Initialize the class and generators
</summary>

<param name="SeedType">The Seed generator that supplies the seed material to the hash function</param>
<param name="DigestType">The Digest type used to post-process the pseudo random seed material</param>
<param name="Counter">The user supplied counter variable in bytes; setting to a <c>0</c> value, produces a counter generated by the default random provider; 
valid values are <c>0</c>, or between <c>4-32</c> bytes</param>

<exception cref="T:CEX.Exception.CryptoGeneratorException">Thrown if the counter is not <c>0</c>, or a value between <c>4</c> and <c>32</c></exception>
</member>
<member name="M:CEX.Common.KeyGenerator.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\keygenerator.h" line="107">
<summary>
Destructor
</summary>
</member>
<member name="M:CEX.Common.KeyGenerator.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\keygenerator.h" line="115">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.Common.KeyGenerator.GetKeyParams(System.UInt32!System.Runtime.CompilerServices.IsConst,System.UInt32!System.Runtime.CompilerServices.IsConst,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\keygenerator.h" line="120">
<summary>
Create a populated KeyParams class
</summary>

<param name="KeySize">Size of Key to generate in bytes</param>
<param name="IVSize">Size of IV to generate in bytes</param>
<param name="IKMSize">Size of IKM to generate in bytes</param>

<returns>A populated <see cref="T:CEX.Common.KeyParams"/> class</returns>
</member>
<member name="M:CEX.Common.KeyGenerator.GetBytes(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced)" decl="true" source="c:\users\john\documents\github\cex\engine\keygenerator.h" line="131">
<summary>
Fill an array with pseudo random bytes
</summary>

<param name="Data">Array to fill with random bytes</param>
</member>
<member name="M:CEX.Common.KeyGenerator.GetBytes(System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\keygenerator.h" line="138">
<summary>
Return an array with pseudo random bytes
</summary>

<param name="Size">Size of requested byte array</param>

<returns>Random byte array</returns>
</member>
<member name="M:CEX.Common.KeyGenerator.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\keygenerator.h" line="147">
<summary>
Reset the seed Seed Generators and the Digest engine
</summary>
</member>
</members>
</doc>