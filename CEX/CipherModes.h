#ifndef CEX_CIPHERMODES_H
#define CEX_CIPHERMODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric cipher mode enumeration names
/// </summary>
enum class CipherModes : uint8_t
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
	/// Electronic CodeBook Mode (not secure: should be used for testing or new constructions only)
	/// </summary>
	ECB = 5,
	/// <summary>
	/// Galois Counter Mode; Counter mode encryption with GMAC authentication
	/// </summary>
	GCM = 6,
	/// <summary>
	/// Block cipher counter-mode with Hash-based Authentication prefix name
	/// </summary>
	HBA = 7,
	/// <summary>
	/// HBA AEAD mode, parameters: CTR(RHXH-256) with HMAC(SHA2-256) Authentication
	/// </summary>
	HBAH256 = 8,
	/// <summary>
	/// HBA AEAD mode, parameters: CTR(RHXH-512) with HMAC(SHA2-512) Authentication
	/// </summary>
	HBAH512 = 9,
	/// <summary>
	/// HBA AEAD mode, parameters: CTR(RHXS-256) with KMAC-256 Authentication
	/// </summary>
	HBAS256 = 10,
	/// <summary>
	/// HBA AEAD mode, parameters: CTR(RHXS-512) with KMAC-512 Authentication
	/// </summary>
	HBAS512 = 11,
	/// <summary>
	/// Little Endian Integer Counter Mode
	/// </summary>
	ICM = 12,
	/// <summary>
	/// Output FeedBack Mode
	/// </summary>
	OFB = 13
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
