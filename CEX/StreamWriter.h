#ifndef CEX_STREAMWRITER_H
#define CEX_STREAMWRITER_H

#include "MemoryStream.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_IO

using Tools::IntegerTools;
using Tools::MemoryTools;

/// <summary>
/// Write integer values to a uint8_t array
/// </summary>
class StreamWriter
{
private:

	size_t m_streamPosition;
	std::vector<uint8_t> m_streamState;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	StreamWriter(const StreamWriter&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	StreamWriter& operator=(const StreamWriter&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	StreamWriter() = delete;

	/// <summary>
	/// Constructor: instantiate this class
	/// </summary>
	///
	/// <param name="Length">The length of the underlying stream</param>
	explicit StreamWriter(size_t Length);

	/// <summary>
	/// Constructor: instantiate this class with a uint8_t array
	/// </summary>
	///
	/// <param name="DataArray">The uint8_t array to write data to</param>
	explicit StreamWriter(const std::vector<uint8_t> &DataArray);

	/// <summary>
	/// Constructor: instantiate this class with a MemoryStream
	/// </summary>
	///
	/// <param name="DataStream">The MemoryStream to write data to</param>
	explicit StreamWriter(MemoryStream &DataStream);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~StreamWriter();

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Returns the entire array of raw bytes from the stream
	/// </summary>
	/// <returns>The array of bytes</returns>
	std::vector<uint8_t> &Generate();

	/// <summary>
	/// Read/Write: Returns the base MemoryStream object
	/// </summary>
	/// <returns>The state as a MemoryStream</returns>
	MemoryStream* GetStream();

	/// <summary>
	/// Read Only: The length of the data
	/// </summary>
	const size_t Length();

	/// <summary>
	/// Read Only: The current position within the data
	/// </summary>
	const size_t Position();

	//~~~Public Functions~~~//

	/// <summary>
	/// Write an array of T to the base stream
	/// </summary>
	/// 
	/// <param name="Input">The T integer source array</param>
	template <typename T>
	void Write(const std::vector<T> &Input)
	{
		const size_t INPLEN = Input.size() * sizeof(T);

		if (m_streamPosition + INPLEN > m_streamState.size())
		{
			m_streamState.resize(m_streamPosition + INPLEN);
		}

		IntegerTools::LeToBlock(Input, 0, m_streamState, m_streamPosition, INPLEN);
		m_streamPosition += INPLEN;
	}

	/// <summary>
	/// Write elements from an array of T to the base stream
	/// </summary>
	/// 
	/// <param name="Input">The T integer source array</param>
	/// <param name="InOffset">The starting offset in the T integer array</param>
	/// <param name="Elements">The number of T integers to write to the array</param>
	template <typename Array>
	void Write(const Array &Input, size_t InOffset, size_t Elements)
	{
		const size_t INPLEN = sizeof(Array::value_type) * Elements;
		if (m_streamPosition + INPLEN > m_streamState.size())
		{
			m_streamState.resize(m_streamPosition + INPLEN);
		}

		if (sizeof(Array::value_type) > 1)
		{
			IntegerTools::LeToBlock(Input, InOffset, m_streamState, m_streamPosition, INPLEN);
		}
		{
			MemoryTools::Copy(Input, InOffset, m_streamState, m_streamPosition, INPLEN);
		}


		m_streamPosition += INPLEN;
	}

	/// <summary>
	/// Write a T sized integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The T integer value</param>
	template <typename T>
	void Write(T Value)
	{
		const size_t VALLEN = sizeof(T);
		if (m_streamPosition + VALLEN > m_streamState.size())
		{
			m_streamState.resize(m_streamPosition + VALLEN);
		}

		switch (VALLEN)
		{
			case 8:
			{
				IntegerTools::Le64ToBytes(Value, m_streamState, m_streamPosition);
				break;
			}
			case 4:
			{
				IntegerTools::Le32ToBytes(Value, m_streamState, m_streamPosition);
				break;
			}
			case 2:
			{
				IntegerTools::Le16ToBytes(Value, m_streamState, m_streamPosition);
				break;
			}
			default:
			{
				MemoryTools::CopyFromValue(Value, m_streamState, m_streamPosition, 1);
				break;
			}
		}

		m_streamPosition += VALLEN;
	}
};

NAMESPACE_IOEND
#endif
