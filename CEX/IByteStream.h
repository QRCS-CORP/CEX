#ifndef _CEXENGINE_ISTREAM_H
#define _CEXENGINE_ISTREAM_H

#include "Common.h"
#include "SeekOrigin.h"
#if defined(CPPEXCEPTIONS_ENABLED)
#	include "CryptoProcessingException.h"
#endif

NAMESPACE_IO

#if defined(CPPEXCEPTIONS_ENABLED)
using CEX::Exception::CryptoProcessingException;
#endif

/// <summary>
/// Data stream object interface
/// </summary>
class IByteStream
{
public:
	// *** Constructor *** //

	/// <summary>
	/// CTor: Initialize this class
	/// </summary>
	IByteStream() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~IByteStream() {}

	// *** Properties *** //

	/// <summary>
	/// Get: The stream can be read
	/// </summary>
	virtual const bool CanRead() = 0;

	/// <summary>
	/// Get: The stream is seekable
	/// </summary>
	virtual const bool CanSeek() = 0;

	/// <summary>
	/// Get: The stream can be written to
	/// </summary>
	virtual const bool CanWrite() = 0;

	/// <summary>
	/// Get: The stream length
	/// </summary>
	virtual const size_t Length() = 0;

	/// <summary>
	/// Get: The streams current position
	/// </summary>
	virtual const size_t Position() = 0;

	// *** Public Methods *** //

	/// <summary>
	/// Close and flush the stream
	/// </summary>
	virtual void Close() = 0;

	/// <summary>
	/// Copy this stream to another stream
	/// </summary>
	///
	/// <param name="Destination">The destination stream</param>
	virtual void CopyTo(IByteStream* Destination) = 0;

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Write the stream to disk
	/// </summary>
	virtual void Flush() = 0;

	/// <summary>
	/// Reads a portion of the stream into the buffer
	/// </summary>
	///
	/// <param name="Buffer">The output buffer receiving the bytes</param>
	/// <param name="Offset">Offset within the output buffer at which to begin</param>
	/// <param name="Count">The number of bytes to read</param>
	///
	/// <returns>The number of bytes processed</returns>
	virtual size_t Read(std::vector<byte> &Buffer, size_t Offset, size_t Count) = 0;

	/// <summary>
	/// Read a single byte from the stream
	/// </summary>
	///
	/// <returns>The byte value</returns>
	virtual byte ReadByte() = 0;

	/// <summary>
	/// Reset and initialize the underlying digest
	/// </summary>
	virtual void Reset() = 0;

	/// <summary>
	/// Seek to a position within the stream
	/// </summary>
	/// 
	/// <param name="Offset">The offset position</param>
	/// <param name="Origin">The starting point</param>
	virtual void Seek(size_t Offset, SeekOrigin Origin) = 0;

	/// <summary>
	/// Set the length of the stream
	/// </summary>
	/// 
	/// <param name="Length">The desired length</param>
	virtual void SetLength(size_t Length) = 0;

	/// <summary>
	/// Writes a buffer into the stream
	/// </summary>
	///
	/// <param name="Buffer">The buffer to write to the stream</param>
	/// <param name="Offset">Offset within the output buffer at which to begin</param>
	/// <param name="Count">The number of bytes to write</param>
	///
	/// <returns>The number of bytes written</returns>
	///
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if Output array is too small</exception>
	virtual void Write(const std::vector<byte> &Buffer, size_t Offset, size_t Count) = 0;

	/// <summary>
	/// Write a single byte from the stream
	/// </summary>
	///
	/// <returns>The byte value</returns>
	virtual void WriteByte(byte Data) = 0;
};

NAMESPACE_IOEND
#endif
