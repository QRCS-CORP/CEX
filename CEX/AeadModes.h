#ifndef CEX_AEADMODES_H
#define CEX_AEADMODES_H

#include "CexDomain.h"
#include "CipherModes.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric AEAD cipher mode enumeration names
/// </summary>
enum class AeadModes : uint8_t
{
	/// <summary>
	/// No cipher mode is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// Galois Counter Mode; Counter mode encryption with GMAC authentication
	/// </summary>
	GCM = static_cast<uint8_t>(CipherModes::GCM),
	/// <summary>
	/// Counter-mode Hash-based Authentication AEAD mode
	/// </summary>
	HBA = static_cast<uint8_t>(CipherModes::HBA),
	/// <summary>
	/// HBA AEAD mode, parameters: CTR(RHXH-256) with HMAC(SHA2-256) Authentication
	/// </summary>
	HBAH256 = static_cast<uint8_t>(CipherModes::HBAH256),
	/// <summary>
	/// HBA AEAD mode, parameters: CTR(RHXH-512) with HMAC(SHA2-512) Authentication
	/// </summary>
	HBAH512 = static_cast<uint8_t>(CipherModes::HBAH512),
	/// <summary>
	/// HBA AEAD mode, parameters: CTR(RHXS-256) with KMAC-256 Authentication
	/// </summary>
	HBAS256 = static_cast<uint8_t>(CipherModes::HBAS256),
	/// <summary>
	/// HBA AEAD mode, parameters: CTR(RHXS-512) with KMAC-512 Authentication
	/// </summary>
	HBAS512 = static_cast<uint8_t>(CipherModes::HBAS512),
};

class AeadModeConvert
{
public:

	/// <summary>
	/// Derive the AeadModes formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The AeadModes enumeration member</param>
	///
	/// <returns>The matching AeadModes string name</returns>
	static std::string ToName(AeadModes Enumeral);

	/// <summary>
	/// Derive the AeadModes enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The AeadModes string name</param>
	///
	/// <returns>The matching AeadModes enumeration type name</returns>
	static AeadModes FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
