#ifndef _CEXENGINE_STREAMREADER_H
#define _CEXENGINE_STREAMREADER_H

#include "MemoryStream.h"

NAMESPACE_IO

/// <summary>
/// Methods for reading integer types from a binary stream
/// </summary>
class StreamReader
{
private:
	CEX::IO::MemoryStream _streamData;
	StreamReader() {}

public:

	/// <summary>
	/// The length of the data
	/// </summary>
	const unsigned int Length() { return _streamData.Length(); }

	/// <summary>
	/// The current position within the data
	/// </summary>
	const unsigned int Position() { return _streamData.Position(); }

	/// <summary>
	/// Initialize this class with a byte array
	/// </summary>
	///
	/// <param name="DataStream">MemoryStream to read</param>
	StreamReader(const CEX::IO::MemoryStream &DataStream)
		:
		_streamData(DataStream)
	{
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	~StreamReader()
	{
	}

	/// <summary>
	/// Read a single byte from the stream
	/// </summary>
	///
	/// <returns>The byte value</returns>
	byte ReadByte();

	/// <summary>
	/// Reads a portion of the stream into the buffer
	/// </summary>
	///
	/// <param name="Length">The number of bytes to read</param>
	///
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	std::vector<byte> ReadBytes(unsigned int Length);

	/// <summary>
	/// Reads a 16 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	short ReadInt16();

	/// <summary>
	/// Reads an unsigned 16 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	unsigned short ReadUInt16();

	/// <summary>
	/// Reads a 32 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	int ReadInt32();

	/// <summary>
	/// Reads an unsigned 32 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	unsigned int ReadUInt32();

	/// <summary>
	/// Reads a 64 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	long ReadInt64();

	/// <summary>
	/// Reads an unsigned 64 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	unsigned long long ReadUInt64();

	/// <summary>
	/// Reads an unsigned 32 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	uint ReadWord32();

	/// <summary>
	/// Reads an unsigned 64 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	ulong ReadWord64();
};

NAMESPACE_IOEND
#endif