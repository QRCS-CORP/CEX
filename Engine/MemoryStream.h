#ifndef _CEXENGINE_MEMORYSTREAM_H
#define _CEXENGINE_MEMORYSTREAM_H

#include "IByteStream.h"

NAMESPACE_IO

/// <summary>
/// Write data to a byte array
/// </summary>
class MemoryStream : public IByteStream
{
private:
	bool _isDestroyed;
	std::vector<byte> _streamData;
	size_t _streamPosition;

public:

	// *** Properties *** //

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
	/// Get: The stream length
	/// </summary>
	virtual const size_t Length() { return _streamData.size(); }

	/// <summary>
	/// Get: The streams current position
	/// </summary>
	virtual const size_t Position() { return _streamPosition; }

	/// <summary>
	/// Get: The underlying stream
	/// </summary>
	std::vector<byte> &ToArray() { return _streamData; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize this class
	/// </summary>
	MemoryStream() 
		:
		_isDestroyed(false),
		_streamData(0),
		_streamPosition(0)
	{
	}

	/// <summary>
	/// Initialize this class; setting the streams length
	/// </summary>
	///
	/// <param name="Length">The reserved length of the stream</param>
	explicit MemoryStream(size_t Length)
		:
		_isDestroyed(false),
		_streamData(0),
		_streamPosition(0)
	{
		_streamData.reserve(Length);
	}

	/// <summary>
	/// Initialize this class; setting a byte array as the streams content
	/// </summary>
	///
	/// <param name="DataArray">The array used to initialize the stream</param>
	explicit MemoryStream(const std::vector<byte> &DataArray)
		:
		_isDestroyed(false),
		_streamData(DataArray),
		_streamPosition(0)
	{
	}

	/// <summary>
	/// Initialize this class (Copy constructor); copy a portion of a byte array to the streams content
	/// </summary>
	/// 
	/// <param name="DataArray">The array used to initialize the stream</param>
	/// <param name="Offset">The offset in the Data array at which to begin copying</param>
	/// <param name="Length">The number of bytes to copy</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if the offset or length values are invalid</exception>
	explicit MemoryStream(std::vector<byte> &DataArray, size_t Offset, size_t Length)
		:
		_isDestroyed(false),
		_streamData(0),
		_streamPosition(0)
	{
		if (Length > DataArray.size() - Offset)
			throw CryptoProcessingException("MemoryStream:CTor", "Length is longer than the array size!");

		_streamData.reserve(Length);
		_streamData.insert(_streamData.begin(), DataArray.begin() + Offset, DataArray.begin() + Length);
	}

	// *** Public Methods *** //

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~MemoryStream()
	{
	}

	// *** Public Methods *** //

	/// <summary>
	/// Close and flush the stream
	/// </summary>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Not implemented exception</exception>
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
	/// Write the stream to disk
	/// </summary>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Not implemented exception</exception>
	virtual void Flush();

	/// <summary>
	/// Reads a portion of the stream into the buffer
	/// </summary>
	///
	/// <param name="Buffer">The output buffer receiving the bytes</param>
	/// <param name="Offset">Offset within the output buffer at which to begin</param>
	/// <param name="Count">The number of bytes to read</param>
	///
	/// <returns>The number of bytes processed</returns>
	virtual size_t Read(std::vector<byte> &Buffer, size_t Offset, size_t Count);

	/// <summary>
	/// Read a single byte from the stream
	/// </summary>
	///
	/// <returns>The byte value</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if the output array is too short</exception>
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
	virtual void Seek(size_t Offset, SeekOrigin Origin);

	/// <summary>
	/// Set the length of the stream
	/// </summary>
	/// 
	/// <param name="Length">The desired length</param>
	virtual void SetLength(size_t Length);

	/// <summary>
	/// Writes a buffer into the stream
	/// </summary>
	///
	/// <param name="Buffer">The output buffer to write to the stream</param>
	/// <param name="Offset">Offset within the output buffer at which to begin</param>
	/// <param name="Count">The number of bytes to write</param>
	///
	/// <returns>The number of bytes processed</returns>
	///
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if Output array is too small</exception>
	virtual void Write(const std::vector<byte> &Buffer, size_t Offset, size_t Count);

	/// <summary>
	/// Write a single byte from the stream
	/// </summary>
	///
	/// <returns>The byte value</returns>
	virtual void WriteByte(byte Data);
};

NAMESPACE_IOEND
#endif