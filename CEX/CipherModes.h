#ifndef CEX_CIPHERMODES_H
#define CEX_CIPHERMODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric cipher mode enumeration names
/// </summary>
enum class CipherModes : byte
{
	/// <summary>
	/// No cipher mode is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// Authenticated Counter Mode
	/// </summary>
	ACM = 1,
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
	/// Electronic CodeBook Mode (not secure: should be used for testing or new constructions only)
	/// </summary>
	ECB = 6,
	/// <summary>
	/// Galois Counter AEAD Mode
	/// </summary>
	GCM = 7,
	/// <summary>
	/// Block cipher counter-mode with Hash-based Authentication, AEAD mode
	/// </summary>
	HBA = 8,
	/// <summary>
	/// Little Endian Integer Counter Mode
	/// </summary>
	ICM = 9,
	/// <summary>
	/// Output FeedBack Mode
	/// </summary>
	OFB = 10
};

class CipherModeConvert
{
public:

	/// <summary>
	/// Derive the CipherModes formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The CipherModes enumeration member</param>
	///
	/// <returns>The matching CipherModes string name</returns>
	static std::string ToName(CipherModes Enumeral);

	/// <summary>
	/// Derive the CipherModes enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The CipherModes string name</param>
	///
	/// <returns>The matching CipherModes enumeration type name</returns>
	static CipherModes FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
