#ifndef CEX_KDFS_H
#define CEX_KDFS_H

#include "CexDomain.h"
#include "Digests.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Key Derivation Functions enumeration names
/// </summary>
enum class Kdfs : uint8_t
{
	/// <summary>
	/// No kdf is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The Hierarchal Key Distribution System: HKDS(SHAKE-128)
	/// </summary>
	HKDS512 = 1,
	/// <summary>
	/// A Hash based Key Derivation Function: HKDF(SHA2-256)
	/// </summary>
	HKDF256 = 2,
	/// <summary>
	/// A Hash based Key Derivation Function: HKDF(SHA2-512)
	/// </summary>
	HKDF512 = 3,
	/// <summary>
	/// An implementation of the Hash based Key Derivation Function: KDF2(SHA2-256)
	/// </summary>
	KDF2256 = 4,
	/// <summary>
	/// An implementation of the Hash based Key Derivation Function: KDF2(SHA2-512)
	/// </summary>
	KDF2512 = 5,
	/// <summary>
	/// An implementation of a Passphrase Based KDF: PBKDF2(SHA2-256)
	/// </summary>
	PBKDF2256 = 6,
	/// <summary>
	/// An implementation of a Passphrase Based KDF: PBKDF2(SHA2-512)
	/// </summary>
	PBKDF2512 = 7,
	/// <summary>
	/// An implementation of the SHAKE-128 XOF function
	/// </summary>
	SHAKE128 = static_cast<uint8_t>(Digests::SHAKE128),
	/// <summary>
	/// An implementation of the SHAKE-256 XOF function
	/// </summary>
	SHAKE256 = static_cast<uint8_t>(Digests::SHAKE256),
	/// <summary>
	/// An implementation of the SHAKE-512 XOF function
	/// </summary>
	SHAKE512 = static_cast<uint8_t>(Digests::SHAKE512),
	/// <summary>
	/// An implementation of SHAKE Cost Based Key Derivation Function SCBKDF(SHAKE128)
	/// </summary>
	SCBKDF128 = 13,
	/// <summary>
	/// An implementation of SHAKE Cost Based Key Derivation Function SCBKDF(SHAKE256)
	/// </summary>
	SCBKDF256 = 14,
	/// <summary>
	/// An implementation of SHAKE Cost Based Key Derivation Function SCBKDF(SHAKE512)
	/// </summary>
	SCBKDF512 = 15,
	/// <summary>
	/// An implementation of SHAKE Cost Based Key Derivation Function SCBKDF(SHAKE1024)
	/// </summary>
	SCBKDF1024 = 16,
	/// <summary>
	/// The Hierarchal Key Distribution System: HKDS(SHAKE-128)
	/// </summary>
	HKDS128 = 20,
	/// <summary>
	/// The Hierarchal Key Distribution System: HKDS(SHAKE-128)
	/// </summary>
	HKDS256 = 21
};

class KdfConvert
{
public:

	/// <summary>
	/// Derive the Kdfs formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The Kdfs enumeration member</param>
	///
	/// <returns>The matching Kdfs string name</returns>
	static std::string ToName(Kdfs Enumeral);

	/// <summary>
	/// Derive the Kdfs enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The Kdfs string name</param>
	///
	/// <returns>The matching Kdfs enumeration type name</returns>
	static Kdfs FromName(std::string &Name);
};
NAMESPACE_ENUMERATIONEND
#endif
