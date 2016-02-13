#ifndef _CEXENGINE_CIPHERMODES_H
#define _CEXENGINE_CIPHERMODES_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Cipher Modes
/// </summary>
enum class CipherModes : uint
{
	/// <summary>
	/// Electronic CodeBook Mode (not secure, testing only)
	/// </summary>
	ECB = 0,
	/// <summary>
	/// Cipher Block Chaining Mode
	/// </summary>
	CBC = 1,
	/// <summary>
	/// Cipher FeedBack Mode
	/// </summary>
	CFB = 2,
	/// <summary>
	/// SIC Counter Mode
	/// </summary>
	CTR = 4,
	/// <summary>
	/// Output FeedBack Mode
	/// </summary>
	OFB = 8
};

NAMESPACE_ENUMERATIONEND
#endif