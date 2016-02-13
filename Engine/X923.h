#ifndef _CEXENGINE_X923_H
#define _CEXENGINE_X923_H

#include "IPadding.h"

NAMESPACE_PADDING

/// <summary>
/// The X.923 Padding Scheme
/// </summary>
class X923 : public IPadding
{
public:
	// *** Constructor *** //

	/// <summary>
	/// Initialize this class
	/// </summary>
	X923() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~X923() {}

	// *** Properties *** //

	/// <summary>
	/// Get: The padding modes type name
	/// </summary>
	virtual const CEX::Enumeration::PaddingModes Enumeral() { return CEX::Enumeration::PaddingModes::X923; }

	/// <summary>
	/// Get: Padding name
	/// </summary>
	virtual const char *Name() { return "X923"; }

	// *** Public Methods *** //

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
