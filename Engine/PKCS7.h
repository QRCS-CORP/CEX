#ifndef _CEXENGINE_PKCS7_H
#define _CEXENGINE_PKCS7_H

#include "IPadding.h"

NAMESPACE_PADDING

/// <summary>
/// The PKCS7 Padding Scheme
/// </summary>
/// 
/// <remarks>
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc5652">5652</a>.</description></item>
/// </list>
/// </remarks>
class PKCS7 : public IPadding
{
public:
	// *** Constructor *** //

	/// <summary>
	/// CTor: Initialize this class
	/// </summary>
	PKCS7() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~PKCS7() {}

	// *** Properties *** //

	/// <summary>
	/// Get: The padding modes type name
	/// </summary>
	virtual const CEX::Enumeration::PaddingModes Enumeral() { return CEX::Enumeration::PaddingModes::PKCS7; }

	/// <summary>
	/// Get: Padding name
	/// </summary>
	virtual const char *Name() { return "PKCS7"; }

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
