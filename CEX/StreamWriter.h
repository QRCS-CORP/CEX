#ifndef _CEX_STREAMWRITER_H
#define _CEX_STREAMWRITER_H

#include "MemoryStream.h"

NAMESPACE_IO

/// <summary>
/// Write integer values to a byte array
/// </summary>
class StreamWriter
{
private:

	size_t m_streamPosition;
	std::vector<byte> m_streamData;

public:

	/// <summary>
	/// The length of the data
	/// </summary>
	const size_t Length() const { return m_streamData.size(); }

	/// <summary>
	/// The current position within the data
	/// </summary>
	const size_t Position() const { return m_streamPosition; }

	/// <summary>
	/// Instantiate this class
	/// </summary>
	///
	/// <param name="Length">The length of the underlying stream</param>
	explicit StreamWriter(size_t Length)
		:
		m_streamData(Length),
		m_streamPosition(0)
	{
	}

	/// <summary>
	/// Instantiate this class with a byte array
	/// </summary>
	///
	/// <param name="DataArray">The byte array to write data to</param>
	explicit StreamWriter(const std::vector<byte> &DataArray)
		:
		m_streamData(DataArray),
		m_streamPosition(0)
	{
	}

	/// <summary>
	/// Instantiate this class with a MemoryStream
	/// </summary>
	///
	/// <param name="DataStream">The MemoryStream to write data to</param>
	explicit StreamWriter(MemoryStream &DataStream)
		:
		m_streamData(DataStream.ToArray()),
		m_streamPosition(0)
	{
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	~StreamWriter()
	{
		Destroy();
	}

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	void Destroy();

	/// <summary>
	/// Returns the entire array of raw bytes from the stream
	/// </summary>
	/// <returns>The array of bytes</returns>
	std::vector<byte> &GetBytes();

	/// <summary>
	/// Returns the base MemoryStream object
	/// </summary>
	/// <returns>The state as a MemoryStream</returns>
	MemoryStream* GetStream();

	/// <summary>
	/// Write an 8bit integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(const byte Value);

	/// <summary>
	/// Write a 16bit integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(const short Value);

	/// <summary>
	/// Write a 16bit unsigned integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(const ushort Value);

	/// <summary>
	/// Write a 32bit integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(const int Value);

	/// <summary>
	/// Write a 32bit unsigned integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(const uint Value);

	/// <summary>
	/// Write a 64bit integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(const long Value);

	/// <summary>
	/// Write a 64bit unsigned integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(const ulong Value);

	/// <summary>
	/// Write an integer array to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	template <typename T>
	void Write(const std::vector<T> &Value)
	{
		size_t sze = sizeof(T) * Value.size();
		if (m_streamPosition + sze > m_streamData.size())
			m_streamData.resize(m_streamPosition + sze);

		memcpy(&m_streamData[m_streamPosition], &Value[0], sze);
		m_streamPosition += sze;
	}
};

NAMESPACE_IOEND
#endif
