#ifndef _CEX_SECURESTREAM_H
#define _CEX_SECURESTREAM_H

#include "IByteStream.h"

NAMESPACE_IO

/// <summary>
/// A secure memory stream container.
/// <para>Manipulate a byte array through a streaming interface.
/// State is encrypted, and only decrypted during read/write operations.</para>
/// </summary>
class SecureStream : public IByteStream
{
private:
	bool m_isDestroyed;
	std::vector<byte> m_keySalt;
	std::vector<byte> m_streamData;
	uint64_t m_streamPosition;

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
	virtual const StreamModes Enumeral() { return StreamModes::SecureStream; }

	/// <summary>
	/// Get: The stream length
	/// </summary>
	virtual const uint64_t Length() { return static_cast<uint64_t>(m_streamData.size()); }

	/// <summary>
	/// Get: The streams current position
	/// </summary>
	virtual const uint64_t Position() { return m_streamPosition; }

	/// <summary>
	/// Get: The underlying stream
	/// </summary>
	std::vector<byte> ToArray() 
	{ 
		if (m_streamData.size() == 0)
			return std::vector<byte>(0);

		Transform();
		std::vector<byte> tmp = m_streamData;
		Transform();

		return tmp; 
	}

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize and empty stream
	/// </summary>
	SecureStream()
		:
		m_isDestroyed(false),
		m_keySalt(0),
		m_streamData(0),
		m_streamPosition(0)
	{
	}

	/// <summary>
	/// Initialize this class and set the streams length
	/// </summary>
	///
	/// <param name="Length">The reserved length of the stream</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	explicit SecureStream(size_t Length, uint64_t KeySalt = 0)
		:
		m_isDestroyed(false),
		m_keySalt(0),
		m_streamData(0),
		m_streamPosition(0)
	{
		if (KeySalt != 0)
		{
			m_keySalt.resize(sizeof(uint64_t));
			memcpy(&m_keySalt[0], &KeySalt, sizeof(uint64_t));
		}

		m_streamData.reserve(Length);
	}

	/// <summary>
	/// Initialize this class with a byte array
	/// </summary>
	///
	/// <param name="Data">The array used to initialize the stream</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	explicit SecureStream(const std::vector<byte> &Data, uint64_t KeySalt = 0)
		:
		m_isDestroyed(false),
		m_keySalt(0),
		m_streamData(Data),
		m_streamPosition(0)
	{
		if (KeySalt != 0)
		{
			m_keySalt.resize(sizeof(uint64_t));
			memcpy(&m_keySalt[0], &KeySalt, sizeof(uint64_t));
		}

		Transform();
	}

	/// <summary>
	/// Initialize this class with a byte array with offset and length parameters
	/// </summary>
	/// 
	/// <param name="Data">The array used to initialize the stream</param>
	/// <param name="Offset">The offset in the Data array at which to begin copying</param>
	/// <param name="Length">The number of bytes to copy</param>
	/// <param name="KeySalt">The secret 64bit salt value used in internal encryption</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if the offset or length values are invalid</exception>
	explicit SecureStream(std::vector<byte> &Data, size_t Offset, size_t Length, uint64_t KeySalt = 0)
		:
		m_isDestroyed(false),
		m_keySalt(0),
		m_streamData(0),
		m_streamPosition(0)
	{
		if (Length > Data.size() - Offset)
			throw CryptoProcessingException("SecureStream:CTor", "Length is longer than the array size!");

		m_streamData.resize(Length);
		memcpy(&m_streamData[0], &Data[Offset], Length);

		if (KeySalt != 0)
		{
			m_keySalt.resize(sizeof(uint64_t));
			memcpy(&m_keySalt[0], &KeySalt, sizeof(uint64_t));
		}

		Transform();
	}

	//~~~Public Methods~~~//

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~SecureStream()
	{
		Destroy();
	}

	//~~~Public Methods~~~//

	/// <summary>
	/// Close and flush the stream (not used in SecureStream)
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
	virtual void Seek(uint64_t Offset, SeekOrigin Origin);

	/// <summary>
	/// Set the length of the stream
	/// </summary>
	/// 
	/// <param name="Length">The desired length</param>
	virtual void SetLength(uint64_t Length);

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

private:
	std::vector<byte> GetSystemKey();
	void Transform();
};

NAMESPACE_IOEND
#endif