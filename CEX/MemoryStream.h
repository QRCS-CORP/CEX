#ifndef _CEX_MEMORYSTREAM_H
#define _CEX_MEMORYSTREAM_H

#include "IByteStream.h"

NAMESPACE_IO

/// <summary>
/// A memory stream container.
/// <para>Manipulate a byte array through a streaming interface.</para>
/// </summary>
class MemoryStream : public IByteStream
{
private:

	bool m_isDestroyed;
	std::vector<byte> m_streamData;
	ulong m_streamPosition;

public:

	//~~~Properties~~~//

	/// <summary>
	/// Get: The stream can be read
	/// </summary>
	virtual const bool CanRead() { return true; }

	/// <summary>
	/// Get: The stream is seekable
	/// </summary>
	virtual const bool CanSeek() { return true; }

	/// <summary>
	/// Get: The stream can be written to
	/// </summary>
	virtual const bool CanWrite() { return true; }

	/// <summary>
	/// Get: The stream container type
	/// </summary>
	virtual const StreamModes Enumeral() { return StreamModes::MemoryStream; }

	/// <summary>
	/// Get: The stream length
	/// </summary>
	virtual const ulong Length() { return static_cast<ulong>(m_streamData.size()); }

	/// <summary>
	/// Get: The streams current position
	/// </summary>
	virtual const ulong Position() { return m_streamPosition; }

	/// <summary>
	/// Get: The underlying stream
	/// </summary>
	std::vector<byte> ToArray() { return m_streamData; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize and empty stream
	/// </summary>
	MemoryStream();

	/// <summary>
	/// Initialize this class and set the streams length
	/// </summary>
	///
	/// <param name="Length">The reserved length of the stream</param>
	explicit MemoryStream(size_t Length);

	/// <summary>
	/// Initialize this class with a byte array
	/// </summary>
	///
	/// <param name="Data">The array used to initialize the stream</param>
	explicit MemoryStream(const std::vector<byte> &Data);

	/// <summary>
	/// Initialize this class with a byte array with offset and length parameters
	/// </summary>
	/// 
	/// <param name="Data">The array used to initialize the stream</param>
	/// <param name="Offset">The offset in the Data array at which to begin copying</param>
	/// <param name="Length">The number of bytes to copy</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if the offset or length values are invalid</exception>
	explicit MemoryStream(const std::vector<byte> &Data, size_t Offset, size_t Length);

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~MemoryStream();

	//~~~Public Functions~~~//

	/// <summary>
	/// Close and flush the stream (not used in MemoryStream)
	/// </summary>
	virtual void Close();

	/// <summary>
	/// Copy this stream to another stream
	/// </summary>
	///
	/// <param name="Destination">The destination stream</param>
	virtual void CopyTo(IByteStream* Destination);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Copies a portion of the stream into an output buffer
	/// </summary>
	///
	/// <param name="Output">The output array receiving the bytes</param>
	/// <param name="Offset">Offset within the output array at which to begin</param>
	/// <param name="Length">The number of bytes to read</param>
	///
	/// <returns>The number of bytes processed</returns>
	virtual size_t Read(std::vector<byte> &Output, size_t Offset, size_t Length);

	/// <summary>
	/// Read a single byte from the stream
	/// </summary>
	///
	/// <returns>The byte value</returns>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if the stream is too short</exception>
	virtual byte ReadByte();

	/// <summary>
	/// Reset and initialize the underlying stream to zero
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Seek to a position within the stream
	/// </summary>
	/// 
	/// <param name="Offset">The offset position</param>
	/// <param name="Origin">The starting point</param>
	virtual void Seek(ulong Offset, SeekOrigin Origin);

	/// <summary>
	/// Set the length of the stream
	/// </summary>
	/// 
	/// <param name="Length">The desired length</param>
	virtual void SetLength(ulong Length);

	/// <summary>
	/// Writes an input buffer to the stream
	/// </summary>
	///
	/// <param name="Input">The input array to write to the stream</param>
	/// <param name="Offset">Offset within the input array at which to begin</param>
	/// <param name="Length">The number of bytes to write</param>
	///
	/// <returns>The number of bytes written</returns>
	///
	/// <exception cref="Exception::CryptoProcessingException">Thrown if Output array is too small</exception>
	virtual void Write(const std::vector<byte> &Input, size_t Offset, size_t Length);

	/// <summary>
	/// Write a single byte from the stream
	/// </summary>
	///
	/// <param name="Value">The byte value to write</param>
	virtual void WriteByte(byte Value);
};

NAMESPACE_IOEND
#endif