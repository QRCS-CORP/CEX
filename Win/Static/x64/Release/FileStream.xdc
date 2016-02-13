<?xml version="1.0"?><doc>
<members>
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
<member name="T:CEX.IO.FileStream" decl="false" source="c:\users\john\documents\github\cex\engine\filestream.h" line="10">
<summary>
Write data values to a file
</summary>
</member>
<member name="T:CEX.IO.FileStream.FileAccess" decl="false" source="c:\users\john\documents\github\cex\engine\filestream.h" line="16">
<summary>
File access type flags
</summary>
</member>
<member name="T:CEX.IO.FileStream.FileMode" decl="false" source="c:\users\john\documents\github\cex\engine\filestream.h" line="26">
<summary>
File operation mode flags
</summary>
</member>
<member name="M:CEX.IO.FileStream.CanRead" decl="false" source="c:\users\john\documents\github\cex\engine\filestream.h" line="54">
<summary>
Get: The stream can be read
</summary>
</member>
<member name="M:CEX.IO.FileStream.CanSeek" decl="false" source="c:\users\john\documents\github\cex\engine\filestream.h" line="59">
<summary>
Get: The stream is seekable
</summary>
</member>
<member name="M:CEX.IO.FileStream.CanWrite" decl="false" source="c:\users\john\documents\github\cex\engine\filestream.h" line="64">
<summary>
Get: The stream can be written to
</summary>
</member>
<member name="M:CEX.IO.FileStream.Length" decl="false" source="c:\users\john\documents\github\cex\engine\filestream.h" line="69">
<summary>
Get: The stream length
</summary>
</member>
<member name="M:CEX.IO.FileStream.Position" decl="false" source="c:\users\john\documents\github\cex\engine\filestream.h" line="74">
<summary>
Get: The streams current position
</summary>
</member>
<member name="M:CEX.IO.FileStream.Stream" decl="false" source="c:\users\john\documents\github\cex\engine\filestream.h" line="79">
<summary>
Get: The underlying stream
</summary>
</member>
<member name="M:CEX.IO.FileStream.#ctor(std.basic_string&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte,std.char_traits{System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte},std.allocator&lt;System.SByte!System.Runtime.CompilerServices.IsSignUnspecifiedByte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,CEX.IO.FileStream.FileAccess,CEX.IO.FileStream.FileMode)" decl="false" source="c:\users\john\documents\github\cex\engine\filestream.h" line="86">
<summary>
Initialize this class
</summary>

<param name="FileName">The full path to the file</param>
<param name="Access">The level of access requested</param>
<param name="Mode">The file processing mode</param>
</member>
<member name="M:CEX.IO.FileStream.Dispose" decl="false" source="c:\users\john\documents\github\cex\engine\filestream.h" line="122">
<summary>
Finalize objects
</summary>
</member>
<member name="M:CEX.IO.FileStream.Close" decl="true" source="c:\users\john\documents\github\cex\engine\filestream.h" line="132">
<summary>
Close and flush the stream
</summary>
</member>
<member name="M:CEX.IO.FileStream.CopyTo(CEX.IO.IByteStream*)" decl="true" source="c:\users\john\documents\github\cex\engine\filestream.h" line="137">
<summary>
Copy this stream to another stream
</summary>

<param name="Destination">The destination stream</param>
</member>
<member name="M:CEX.IO.FileStream.Destroy" decl="true" source="c:\users\john\documents\github\cex\engine\filestream.h" line="144">
<summary>
Release all resources associated with the object
</summary>
</member>
<member name="M:CEX.IO.FileStream.Flush" decl="true" source="c:\users\john\documents\github\cex\engine\filestream.h" line="149">
<summary>
Write the stream to disk
</summary>
</member>
<member name="M:CEX.IO.FileStream.Read(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\filestream.h" line="154">
<summary>
Reads a portion of the stream into the buffer
</summary>

<param name="Buffer">The output buffer receiving the bytes</param>
<param name="Offset">Offset within the output buffer at which to begin</param>
<param name="Count">The number of bytes to read</param>

<returns>The number of bytes processed</returns>
</member>
<member name="M:CEX.IO.FileStream.ReadByte" decl="true" source="c:\users\john\documents\github\cex\engine\filestream.h" line="165">
<summary>
Read a single byte from the stream
</summary>

<returns>The byte value</returns>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if the stream is too short or the file is write only</exception>
</member>
<member name="M:CEX.IO.FileStream.Reset" decl="true" source="c:\users\john\documents\github\cex\engine\filestream.h" line="174">
<summary>
Reset and initialize the underlying stream to zero
</summary>
</member>
<member name="M:CEX.IO.FileStream.Seek(System.UInt32,&lt;unknown type&gt;)" decl="true" source="c:\users\john\documents\github\cex\engine\filestream.h" line="179">
<summary>
Seek to a position within the stream
</summary>

<param name="Offset">The offset position</param>
<param name="Origin">The starting point</param>
</member>
<member name="M:CEX.IO.FileStream.SetLength(System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\filestream.h" line="187">
<summary>
Set the length of the stream
</summary>

<param name="Length">The desired length</param>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if the file is read only</exception>
</member>
<member name="M:CEX.IO.FileStream.Write(std.vector&lt;System.Byte,std.allocator&lt;System.Byte&gt;&gt;!System.Runtime.CompilerServices.IsConst*!System.Runtime.CompilerServices.IsImplicitlyDereferenced,System.UInt32,System.UInt32)" decl="true" source="c:\users\john\documents\github\cex\engine\filestream.h" line="196">
<summary>
Writes a buffer into the stream
</summary>

<param name="Buffer">The output buffer to write to the stream</param>
<param name="Offset">Offset within the output buffer at which to begin</param>
<param name="Count">The number of bytes to write</param>

<returns>The number of bytes processed</returns>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if the file is read only</exception>
</member>
<member name="M:CEX.IO.FileStream.WriteByte(System.Byte)" decl="true" source="c:\users\john\documents\github\cex\engine\filestream.h" line="209">
<summary>
Write a single byte from the stream
</summary>

<returns>The byte value</returns>

<exception cref="T:CEX.Exception.CryptoProcessingException">Thrown if the file is read only</exception>
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
</members>
</doc>