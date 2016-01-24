#ifndef _CEXENGINE_MEMORYSTREAM_H
#define _CEXENGINE_MEMORYSTREAM_H

#include "Common.h"
#include "IByteStream.h"
#include "SeekOrigin.h"

NAMESPACE_IO

using CEX::IO::SeekOrigin;

/// <summary>
/// Write data to a byte array
/// </summary>
class MemoryStream : public IByteStream
{
private:
	bool _isDestroyed;
	std::vector<byte> _streamData;
	unsigned int _streamPosition;

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
	virtual const unsigned int Length() { return _streamData.size(); }

	/// <summary>
	/// Get: The streams current position
	/// </summary>
	virtual const unsigned int Position() { return _streamPosition; }

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
	MemoryStream(unsigned int Length)
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
	MemoryStream(std::vector<byte> &Data)
		:
		_isDestroyed(false),
		_streamData(Data),
		_streamPosition(0)
	{
	}

	/// <summary>
	/// Initialize this class (Copy constructor); copy a portion of a byte array to the streams content
	/// </summary>
	/// 
	/// <param name="Offset">The offset in the Data array at which to begin copying</param>
	/// <param name="Length">The number of bytes to copy</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if the offset or length values are invalid</exception>
	MemoryStream(std::vector<byte> &Data, unsigned int Offset, unsigned int Length)
		:
		_isDestroyed(false),
		_streamData(0),
		_streamPosition(0)
	{
		if (Length > Data.size() - Offset)
			throw CryptoProcessingException("MemoryStream:CTor", "Length is longer than the array size!");

		_streamData.reserve(Length);
		_streamData.insert(_streamData.begin(), Data.begin() + Offset, Data.begin() + Length);
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
	virtual int Read(std::vector<byte> &Buffer, unsigned int Offset, unsigned int Count);

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
	virtual void Seek(unsigned int Offset, SeekOrigin Origin);

	/// <summary>
	/// Set the length of the stream
	/// </summary>
	/// 
	/// <param name="Offset">The desired length</param>
	virtual void SetLength(unsigned int Length);

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
	virtual void Write(const std::vector<byte> &Buffer, unsigned int Offset, unsigned int Count);

	/// <summary>
	/// Write a single byte from the stream
	/// </summary>
	///
	/// <returns>The byte value</returns>
	virtual void WriteByte(byte Data);
};

NAMESPACE_IOEND
#endif