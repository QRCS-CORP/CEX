#ifndef CEX_CIPHERMODES_H
#define CEX_CIPHERMODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric cipher mode enmumeration names
/// </summary>
enum class CipherModes : byte
{
	/// <summary>
	/// No cipher mode is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// Electronic CodeBook Mode (not secure, testing only)
	/// </summary>
	ECB = 1,
	/// <summary>
	/// Cipher Block Chaining Mode
	/// </summary>
	CBC = 2,
	/// <summary>
	/// Cipher FeedBack Mode
	/// </summary>
	CFB = 3,
	/// <summary>
	/// Big Endian Segmented Integer Counter Mode
	/// </summary>
	CTR = 4,
	/// <summary>
	/// Encrypt and Authenticate AEAD Mode
	/// </summary>
	EAX = 5,
	/// <summary>
	/// Galois Counter AEAD Mode
	/// </summary>
	GCM = 6,
	/// <summary>
	/// Little Endian Integer Counter Mode
	/// </summary>
	ICM = 7,
	/// <summary>
	/// Offset CodeBook AEAD Mode
	/// </summary>
	OCB = 8,
	/// <summary>
	/// Output FeedBack Mode
	/// </summary>
	OFB = 9
};

NAMESPACE_ENUMERATIONEND
#endif
