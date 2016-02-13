#ifndef _CEXENGINE_STREAMWRITER_H
#define _CEXENGINE_STREAMWRITER_H

#include "MemoryStream.h"

NAMESPACE_IO

/// <summary>
/// Write integer values to a byte array
/// </summary>
class StreamWriter
{
private:
	size_t _streamPosition;
	std::vector<byte> _streamData;

public:

	/// <summary>
	/// The length of the data
	/// </summary>
	const size_t Length() const { return _streamData.size(); }

	/// <summary>
	/// The current position within the data
	/// </summary>
	const size_t Position() const { return _streamPosition; }

	/// <summary>
	/// Initialize this class
	/// </summary>
	///
	/// <param name="Length">The length of the underlying stream</param>
	explicit StreamWriter(size_t Length)
		:
		_streamData(Length),
		_streamPosition(0)
	{
	}

	/// <summary>
	/// Initialize this class with a byte array
	/// </summary>
	///
	/// <param name="DataArray">The byte array to write data to</param>
	explicit StreamWriter(std::vector<byte> &DataArray)
		:
		_streamData(DataArray),
		_streamPosition(0)
	{
	}

	/// <summary>
	/// Initialize this class with a MemoryStream
	/// </summary>
	///
	/// <param name="DataStream">The MemoryStream to write data to</param>
	explicit StreamWriter(MemoryStream &DataStream)
		:
		_streamData(DataStream.ToArray()),
		_streamPosition(0)
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
	void Write(byte Value);

	/// <summary>
	/// Write a 16bit integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(short Value);

	/// <summary>
	/// Write a 16bit unsigned integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(ushort Value);

	/// <summary>
	/// Write a 32bit integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(int Value);

	/// <summary>
	/// Write a 32bit unsigned integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(uint Value);

	/// <summary>
	/// Write a 64bit integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(long Value);

	/// <summary>
	/// Write a 64bit unsigned integer to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(ulong Value);


	template <class T>
	/// <summary>
	/// Write an integer array to the base stream
	/// </summary>
	/// 
	/// <param name="Value">The integer value</param>
	void Write(std::vector<T> &Value)
	{
		size_t sze = sizeof(T) * Value.size();
		if (_streamPosition + sze > _streamData.size())
			_streamData.resize(_streamPosition + sze);

		memcpy(&_streamData[_streamPosition], &Value[0], sze);
		_streamPosition += sze;
	}
};

NAMESPACE_IOEND
#endif
