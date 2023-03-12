#ifndef CEX_ECDHPARAMETERS_H
#define CEX_ECDHPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricParameters.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The Elliptic Curve Digital Signature Alogorithm parameter sets enumeration
/// </summary>
enum class ECDSAParameters : uint8_t
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The ECDSA S1 parameter; elliptic ED25519 curve using the SHA3-512 digest (Keccak)
	/// </summary>
	ECDSAS1ED25519K = static_cast<uint8_t>(AsymmetricParameters::ECDSAS1ED25519K),
	/// <summary>
	/// The ECDSA S2 parameter; elliptic ED25519 curve using the SHA2-512 digest
	/// </summary>
	ECDSAS2ED25519S = static_cast<uint8_t>(AsymmetricParameters::ECDSAS2ED25519S)
};

class ECDSAParameterConvert
{
public:

	/// <summary>
	/// Derive the ECDSAParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The ECDSAParameters enumeration member</param>
	///
	/// <returns>The matching ECDSAParameters string name</returns>
	static std::string ToName(ECDSAParameters Enumeral);

	/// <summary>
	/// Derive the ECDSAParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The ECDSAParameters string name</param>
	///
	/// <returns>The matching ECDSAParameters enumeration type name</returns>
	static ECDSAParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
