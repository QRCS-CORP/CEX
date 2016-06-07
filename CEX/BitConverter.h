#ifndef _CEXENGINE_BITCONVERTER_H
#define _CEXENGINE_BITCONVERTER_H

#include "Common.h"

NAMESPACE_IO

/// <summary>
/// Converts bytes to integers
/// </summary>
class BitConverter
{
public:

	/// <summary>
	/// Convert bytes to a char value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A char value</returns>
	static char ToChar(const std::vector<byte> &Input, const size_t InOffset)
	{
		char d = 0;
		size_t sze = sizeof(char);
		memcpy(&d, &Input[InOffset], sze);
		return d;
	}

	/// <summary>
	/// Convert bytes to an unsigned char value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>An unsigned char value</returns>
	static unsigned char ToUChar(const std::vector<byte> &Input, const size_t InOffset)
	{
		unsigned char d = 0;
		size_t sze = sizeof(unsigned char);
		memcpy(&d, &Input[InOffset], sze);
		return d;
	}

	/// <summary>
	/// Convert bytes to a double value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A double value</returns>
	static double ToDouble(const std::vector<byte> &Input, const size_t InOffset)
	{
		double d = 0;
		size_t sze = sizeof(double);
		memcpy(&d, &Input[InOffset], sze);
		return d;
	}

	/// <summary>
	/// Convert bytes to a float value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A float value</returns>
	static float ToFloat(const std::vector<byte> &Input, const size_t InOffset)
	{
		float d = 0;
		size_t sze = sizeof(float);
		memcpy(&d, &Input[InOffset], sze);
		return d;
	}

	/// <summary>
	/// Convert bytes to a 16 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A 16 bit integer value</returns>
	static short ToInt16(const std::vector<byte> &Input, const size_t InOffset)
	{
		short d = 0;
		size_t sze = sizeof(short);
		memcpy(&d, &Input[InOffset], sze);
		return d;
	}

	/// <summary>
	/// Convert bytes to an unsigned 16 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>An unsigned 16 bit integer value</returns>
	static ushort ToUInt16(const std::vector<byte> &Input, const size_t InOffset)
	{
		unsigned short d = 0;
		size_t sze = sizeof(unsigned short);
		memcpy(&d, &Input[InOffset], sze);
		return d;
	}

	/// <summary>
	/// Convert bytes to a 32 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A 32 bit integer value</returns>
	static int ToInt32(const std::vector<byte> &Input, const size_t InOffset)
	{
		int d = 0;
		size_t sze = sizeof(int);
		memcpy(&d, &Input[InOffset], sze);
		return d;
	}

	/// <summary>
	/// Convert bytes to an unsigned 32 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>An unsigned 32 bit integer value</returns>
	static uint ToUInt32(const std::vector<byte> &Input, const uint InOffset)
	{
		uint d = 0;
		size_t sze = sizeof(uint);
		memcpy(&d, &Input[InOffset], sze);
		return d;
	}

	/// <summary>
	/// Convert bytes to a 64 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A 64 bit integer value</returns>
	static long ToInt64(const std::vector<byte> &Input, const size_t InOffset)
	{
		long d = 0;
		size_t sze = sizeof(long);
		memcpy(&d, &Input[InOffset], sze);
		return d;
	}

	/// <summary>
	/// Convert bytes to an unsigned 64 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>An unsigned 64 bit integer value</returns>
	static ulong ToUInt64(const std::vector<byte> &Input, const size_t InOffset)
	{
		ulong d = 0;
		size_t sze = sizeof(ulong);
		memcpy(&d, &Input[InOffset], sze);
		return d;
	}
};
NAMESPACE_IOEND
#endif

