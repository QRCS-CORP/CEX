#ifndef _CEXENGINE_PKCS7_H
#define _CEXENGINE_PKCS7_H

#include "IPadding.h"

NAMESPACE_PADDING

/// <summary>
/// The PKCS7 Padding Scheme.
/// <para>PKCS7 as outlined in RFC 5652: <see href="http://tools.ietf.org/html/rfc5652"/></para>
/// </summary>
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
	virtual const PaddingModes Enumeral() { return PaddingModes::PKCS7; }

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
