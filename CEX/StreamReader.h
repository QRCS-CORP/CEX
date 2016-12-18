#ifndef _CEX_STREAMREADER_H
#define _CEX_STREAMREADER_H

#include "MemoryStream.h"

NAMESPACE_IO

/// <summary>
/// Methods for reading integer types from a binary stream
/// </summary>
class StreamReader
{
private:
	MemoryStream m_streamData;
	StreamReader() {}

public:

	/// <summary>
	/// The length of the data
	/// </summary>
	const size_t Length() { return m_streamData.Length(); }

	/// <summary>
	/// The current position within the data
	/// </summary>
	const size_t Position() { return m_streamData.Position(); }

	/// <summary>
	/// Instantiate this class with a byte array
	/// </summary>
	///
	/// <param name="DataStream">MemoryStream to read</param>
	explicit StreamReader(const MemoryStream &DataStream)
		:
		m_streamData(DataStream)
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
	/// <exception cref="Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	std::vector<byte> ReadBytes(size_t Length);

	/// <summary>
	/// Reads a 16 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	short ReadInt16();

	/// <summary>
	/// Reads an unsigned 16 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	ushort ReadUInt16();

	/// <summary>
	/// Reads a 32 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	int ReadInt32();

	/// <summary>
	/// Reads an unsigned 32 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	uint ReadUInt32();

	/// <summary>
	/// Reads a 64 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	long ReadInt64();

	/// <summary>
	/// Reads an unsigned 64 bit integer from the stream
	/// </summary>
	///
	/// <exception cref="Exception::CryptoProcessingException">Thrown if source array is too small</exception>
	ulong ReadUInt64();
};

NAMESPACE_IOEND
#endif