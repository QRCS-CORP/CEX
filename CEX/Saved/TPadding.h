#ifndef _CEXENGINE_TPADDING_H
#define _CEXENGINE_TPADDING_H

#include "Common.h"
#include "CryptoPaddingException.h"
#include "PaddingModes.h"

NAMESPACE_PADDING

using CEX::Exception::CryptoPaddingException;

/// <summary>
/// Padding Mode Template
/// </summary>
template <typename Base>
class Padding : public Base
{
private:
	Base& base() { return *static_cast<Base*>(this); }
	const Base& base() const { return *static_cast<const Base*>(this); }

protected:

	// *** Properties *** //

	/// <summary>
	/// Get: The padding modes type name
	/// </summary>
	const CEX::Enumeration::PaddingModes Enumeral() {}

	/// <summary>
	/// Get: Padding name
	/// </summary>
	const char *Name() {}

	// *** Public Methods *** //

	/// <summary>
	/// Add padding to input array
	/// </summary>
	///
	/// <param name="Input">Array to modify</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	size_t AddPadding(std::vector<byte> &Input, size_t Offset) {}

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	///
	/// <returns>Length of padding</returns>
	size_t GetPaddingLength(const std::vector<byte> &Input) {}

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	size_t GetPaddingLength(const std::vector<byte> &Input, size_t Offset) {}
};

NAMESPACE_PADDINGEND
#endif

