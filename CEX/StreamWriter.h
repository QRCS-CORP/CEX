#ifndef _CEX_STREAMWRITER_H
#define _CEX_STREAMWRITER_H

#include "MemoryStream.h"
#include "MemUtils.h"

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
	/// Instantiate this class
	/// </summary>
	///
	/// <param name="Length">The length of the underlying stream</param>
	explicit StreamWriter(size_t Length);

	/// <summary>
	/// Instantiate this class with a byte array
	/// </summary>
	///
	/// <param name="DataArray">The byte array to write data to</param>
	explicit StreamWriter(const std::vector<byte> &DataArray);

	/// <summary>
	/// Instantiate this class with a MemoryStream
	/// </summary>
	///
	/// <param name="DataStream">The MemoryStream to write data to</param>
	explicit StreamWriter(MemoryStream &DataStream);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~StreamWriter();

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
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
	/// Write an array of T to the base stream
	/// </summary>
	/// 
	/// <param name="Input">The T integer source array</param>
	template <typename T>
	void Write(const std::vector<T> &Input)
	{
		const size_t INPSZE = Input.size() * sizeof(T);
		if (m_streamPosition + INPSZE > m_streamData.size())
			m_streamData.resize(m_streamPosition + INPSZE);

		Utility::MemUtils::Copy<T, byte>(Input, 0, m_streamData, m_streamPosition, INPSZE);
		m_streamPosition += INPSZE;
	}

	/// <summary>
	/// Write elements from an array of T to the base stream
	/// </summary>
	/// 
	/// <param name="Input">The T integer source array</param>
	/// <param name="InOffset">The starting offset in the T integer array</param>
	/// <param name="Length">The number of T integers to write to the array</param>
	template <typename T>
	void Write(const std::vector<T> &Input, size_t InOffset, size_t Elements)
	{
		const size_t INPSZE = sizeof(T) * Elements;
		if (m_streamPosition + INPSZE > m_streamData.size())
			m_streamData.resize(m_streamPosition + INPSZE);

		Utility::MemUtils::Copy<T, byte>(Input, InOffset, m_streamData, m_streamPosition, INPSZE);
		m_streamPosition += INPSZE;
	}

	/// <summary>
	/// Write a T sized integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The T integer value</param>
	template <typename T>
	void Write(T Value)
	{
		const size_t VALSZE = sizeof(T);
		if (m_streamPosition + VALSZE > m_streamData.size())
			m_streamData.resize(m_streamPosition + VALSZE);

		Utility::MemUtils::Copy<T, byte>(Value, m_streamData, m_streamPosition, VALSZE);
		m_streamPosition += VALSZE;
	}
};

NAMESPACE_IOEND
#endif
