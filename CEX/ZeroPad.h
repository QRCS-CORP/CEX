#ifndef _CEXENGINE_ZEROPAD_H
#define _CEXENGINE_ZEROPAD_H

#include "IPadding.h"

NAMESPACE_PADDING

/// <summary>
/// The Zero Padding Scheme (Not Recommended).
/// </summary>
class ZeroPad : public IPadding
{
public:
	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Initialize this class
	/// </summary>
	ZeroPad() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~ZeroPad() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: The padding modes type name
	/// </summary>
	virtual const PaddingModes Enumeral() { return PaddingModes::None; }

	/// <summary>
	/// Get: Padding name
	/// </summary>
	virtual const char *Name() { return "ZeroPad"; }

	//~~~Public Methods~~~//

	/// <summary>
	/// Add padding to input array
	/// </summary>
	///
	/// <param name="Input">Array to modify</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	///
	/// <exception cref="CEX::Exception::CryptoPaddingException">Thrown if the padding offset value is longer than the array length</exception>
	virtual size_t AddPadding(std::vector<byte> &Input, size_t Offset);

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	///
	/// <returns>Length of padding</returns>
	virtual size_t GetPaddingLength(const std::vector<byte> &Input);

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	virtual size_t GetPaddingLength(const std::vector<byte> &Input, size_t Offset);
};

NAMESPACE_PADDINGEND
#endif

