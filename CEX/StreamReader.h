#ifndef CEX_STREAMREADER_H
#define CEX_STREAMREADER_H

#include "MemoryStream.h"
#include "IntUtils.h"
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

	//~~~Constructor~~~//

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	StreamReader& operator=(const StreamReader&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	StreamReader() = delete;

	/// <summary>
	/// Constructor: instantiate this class with a byte array
	/// </summary>
	///
	/// <param name="DataStream">MemoryStream to read</param>
	explicit StreamReader(const MemoryStream &DataStream);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~StreamReader();

	//~~~Accessors~~~//

	/// <summary>
	/// The length of the data
	/// </summary>
	const size_t Length();

	/// <summary>
	/// The current position within the data
	/// </summary>
	const size_t Position();

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
	/// Read elements from the base stream into an array of T
	/// </summary>
	/// 
	/// <param name="Output">The T integer output array</param>
	/// <param name="OutOffset">The starting offset in the T integer array</param>
	/// <param name="Elements">The number of T integers to write to the array</param>
	template <typename Array>
	size_t Read(const Array &Output, size_t OutOffset, size_t Elements)
	{
		const size_t OTPLEN = (m_streamData.Position() + (sizeof(Array::value_type) * Elements)) > m_streamData.size() ?
			(m_streamData.size() - m_streamData.Position() - ()) :
			sizeof(Array::value_type) * Elements;

		if (sizeof(Array::value_type) > 1)
		{
			Utility::IntUtils::BlockToLe(m_streamData.ToArray(), m_streamData.Position(), Output, OutOffset, OTPLEN);
		}
		{
			Utility::MemUtils::Copy(m_streamData.ToArray(), m_streamData.Position(), val, OTPLEN);
		}

		m_streamData.Seek(m_streamData.Position() + OTPLEN, SeekOrigin::Begin);
	}

	/// <summary>
	/// Reads a T integer from the stream
	/// </summary>
	template <typename T>
	T ReadInt()
	{
		const size_t VALLEN = sizeof(T);

		CexAssert(m_streamData.Position() + VALLEN <= m_streamData.Length(), "Stream length exceeded");

		T val = 0;

		switch (VALLEN)
		{
			case 8:
			{
				val = Utility::IntUtils::LeBytesTo64(m_streamData.ToArray(), m_streamData.Position());
				break;
			}
			case 4:
			{
				val = Utility::IntUtils::LeBytesTo32(m_streamData.ToArray(), m_streamData.Position());
				break;
			}
			case 2:
			{
				val = Utility::IntUtils::LeBytesTo16(m_streamData.ToArray(), m_streamData.Position());
				break;
			}
			default:
			{
				Utility::MemUtils::CopyToValue(m_streamData.ToArray(), m_streamData.Position(), val, VALLEN);
			}
		}

		m_streamData.Seek(m_streamData.Position() + VALLEN, SeekOrigin::Begin);

		return val;
	}
};

NAMESPACE_IOEND
#endif
