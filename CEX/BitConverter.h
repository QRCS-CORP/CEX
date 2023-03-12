#ifndef CEX_BITCONVERTER_H
#define CEX_BITCONVERTER_H

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
	/// <param name="Input">The Input uint8_t array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A char value</returns>
	static char ToChar(const std::vector<uint8_t> &Input, size_t InOffset);

	/// <summary>
	/// Convert bytes to an uint8_t value
	/// </summary>
	/// 
	/// <param name="Input">The Input uint8_t array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>An uint8_t value</returns>
	static uint8_t ToUChar(const std::vector<uint8_t> &Input, size_t InOffset);

	/// <summary>
	/// Convert bytes to a double value
	/// </summary>
	/// 
	/// <param name="Input">The Input uint8_t array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A double value</returns>
	static double ToDouble(const std::vector<uint8_t> &Input, size_t InOffset);

	/// <summary>
	/// Convert bytes to a float value
	/// </summary>
	/// 
	/// <param name="Input">The Input uint8_t array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A float value</returns>
	static float ToFloat(const std::vector<uint8_t> &Input, size_t InOffset);

	/// <summary>
	/// Convert bytes to a 16 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input uint8_t array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A 16 bit integer value</returns>
	static int16_t ToInt16(const std::vector<uint8_t> &Input, size_t InOffset);

	/// <summary>
	/// Convert bytes to an unsigned 16 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input uint8_t array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>An unsigned 16 bit integer value</returns>
	static uint16_t ToUInt16(const std::vector<uint8_t> &Input, size_t InOffset);

	/// <summary>
	/// Convert bytes to a 32 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input uint8_t array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A 32 bit integer value</returns>
	static int32_t ToInt32(const std::vector<uint8_t> &Input, size_t InOffset);

	/// <summary>
	/// Convert bytes to an unsigned 32 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input uint8_t array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>An unsigned 32 bit integer value</returns>
	static uint32_t ToUInt32(const std::vector<uint8_t> &Input, size_t InOffset);

	/// <summary>
	/// Convert bytes to a 64 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input uint8_t array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>A 64 bit integer value</returns>
	static int64_t ToInt64(const std::vector<uint8_t> &Input, size_t InOffset);

	/// <summary>
	/// Convert bytes to an unsigned 64 bit integer value
	/// </summary>
	/// 
	/// <param name="Input">The Input uint8_t array</param>
	/// <param name="InOffset">The starting position within the Input array</param>
	/// 
	/// <returns>An unsigned 64 bit integer value</returns>
	static uint64_t ToUInt64(const std::vector<uint8_t> &Input, size_t InOffset);
};

NAMESPACE_IOEND
#endif

