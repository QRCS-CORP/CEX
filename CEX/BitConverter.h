#ifndef _CEX_BITCONVERTER_H
#define _CEX_BITCONVERTER_H

#include "CexDomain.h"

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
	static char ToChar(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert bytes to an unsigned char value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>An unsigned char value</returns>
	static unsigned char ToUChar(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert bytes to a double value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A double value</returns>
	static double ToDouble(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert bytes to a float value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A float value</returns>
	static float ToFloat(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert bytes to a 16 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A 16 bit integer value</returns>
	static short ToInt16(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert bytes to an unsigned 16 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>An unsigned 16 bit integer value</returns>
	static ushort ToUInt16(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert bytes to a 32 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A 32 bit integer value</returns>
	static int ToInt32(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert bytes to an unsigned 32 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>An unsigned 32 bit integer value</returns>
	static uint ToUInt32(const std::vector<byte> &Input, const uint InOffset);

	/// <summary>
	/// Convert bytes to a 64 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A 64 bit integer value</returns>
	static long ToInt64(const std::vector<byte> &Input, const size_t InOffset);

	/// <summary>
	/// Convert bytes to an unsigned 64 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input byte array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>An unsigned 64 bit integer value</returns>
	static ulong ToUInt64(const std::vector<byte> &Input, const size_t InOffset);
};

NAMESPACE_IOEND
#endif

