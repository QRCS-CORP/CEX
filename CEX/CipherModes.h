#ifndef _CEX_CIPHERMODES_H
#define _CEX_CIPHERMODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Symmetric cipher mode enmumeration names
/// </summary>
enum class CipherModes : uint8_t
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
	CFB = 4,
	/// <summary>
	/// Big Endian Segmented Integer Counter Mode
	/// </summary>
	CTR = 8,
	/// <summary>
	/// Galois Counter Mode
	/// </summary>
	GCM = 16,
	/// <summary>
	/// Little Endian Integer Counter Mode
	/// </summary>
	ICM = 32,
	/// <summary>
	/// Output FeedBack Mode
	/// </summary>
	OFB = 64
};

NAMESPACE_ENUMERATIONEND
#endif