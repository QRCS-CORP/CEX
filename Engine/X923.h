#ifndef _CEXENGINE_X923_H
#define _CEXENGINE_X923_H

#include "CSPRsg.h"
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
	virtual const PaddingModes Enumeral() { return PaddingModes::X923; }

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
	virtual unsigned int AddPadding(std::vector<byte> &Input, unsigned int Offset);

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	///
	/// <returns>Length of padding</returns>
	virtual unsigned int GetPaddingLength(const std::vector<byte> &Input);

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	virtual unsigned int GetPaddingLength(const std::vector<byte> &Input, unsigned int Offset);
};

NAMESPACE_PADDINGEND
#endif
