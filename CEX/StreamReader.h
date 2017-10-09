#ifndef CEX_STREAMREADER_H
#define CEX_STREAMREADER_H

#include "MemoryStream.h"
#include "MemUtils.h"

NAMESPACE_IO

/// <summary>
/// Methods for reading integer types from a binary stream
/// </summary>
class StreamReader
{
private:

	MemoryStream m_streamData;

public:

	StreamReader() = delete;
	StreamReader(const StreamReader&) = delete;
	StreamReader& operator=(const StreamReader&) = delete;
	StreamReader& operator=(StreamReader&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// The length of the data
	/// </summary>
	const size_t Length();

	/// <summary>
	/// The current position within the data
	/// </summary>
	const size_t Position();

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate this class with a byte array
	/// </summary>
	///
	/// <param name="DataStream">MemoryStream to read</param>
	explicit StreamReader(const MemoryStream &DataStream);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~StreamReader();

	//~~~Public Functions~~~//

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
	std::vector<byte> ReadBytes(size_t Length);

	/// <summary>
	/// Reads a T integer from the stream
	/// </summary>
	template <typename T>
	T ReadInt()
	{
		const size_t VALSZE = sizeof(T);
		CexAssert(m_streamData.Position() + VALSZE <= m_streamData.Length(), "Stream length exceeded");
		T val = 0;
		Utility::MemUtils::CopyToValue(m_streamData.ToArray(), m_streamData.Position(), val, sizeof(val));
		m_streamData.Seek(m_streamData.Position() + VALSZE, SeekOrigin::Begin);

		return val;
	}
};

NAMESPACE_IOEND
#endif