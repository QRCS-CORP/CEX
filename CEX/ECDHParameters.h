#ifndef CEX_ECDHPARAMETERS_H
#define CEX_ECDHPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricParameters.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The Elliptic Curve Diffie Hellman parameter sets enumeration
/// </summary>
enum class ECDHParameters : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The ECDH S1 parameter; elliptic 25519 curve using the SHA3-512 digest (Keccak)
	/// </summary>
	ECDHS1EC25519K = static_cast<byte>(AsymmetricParameters::ECDHS1EC25519K),
	/// <summary>
	/// The ECDH S2 parameter; elliptic 25519 curve using the SHA2-512 digest
	/// </summary>
	ECDHS2EC25519S = static_cast<byte>(AsymmetricParameters::ECDHS2EC25519S)
};

class ECDHParameterConvert
{
public:

	/// <summary>
	/// Derive the ECDHParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The ECDHParameters enumeration member</param>
	///
	/// <returns>The matching ECDHParameters string name</returns>
	static std::string ToName(ECDHParameters Enumeral);

	/// <summary>
	/// Derive the ECDHParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The ECDHParameters string name</param>
	///
	/// <returns>The matching ECDHParameters enumeration type name</returns>
	static ECDHParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
