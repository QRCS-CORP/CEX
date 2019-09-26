#ifndef CEX_SPHINCSPARAMETERS_H
#define CEX_SPHINCSPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricParameters.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The SPHINCS+ parameter sets enumeration
/// </summary>
enum class SphincsPlusParameters : byte
{
	/// <summary>
	/// No parameter is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters; (Medium Security) The SphincsPlus SHAKE256, S128 parameter set
	/// </summary>
	SPXPS1S128SHAKE = static_cast<byte>(AsymmetricParameters::SPXPS1S128SHAKE),
	/// <summary>
	/// The S2 parameters; (High Security) The SphincsPlus SHAKE256, S192 parameter set
	/// </summary>
	SPXPS2S192SHAKE = static_cast<byte>(AsymmetricParameters::SPXPS2S192SHAKE),
	/// <summary>
	/// The S3 parameters; (Highest Security) The SphincsPlus SHAKE256, S256 parameter set
	/// </summary>
	SPXPS3S256SHAKE = static_cast<byte>(AsymmetricParameters::SPXPS3S256SHAKE)
};

class SphincsPlusParameterConvert
{
public:

	/// <summary>
	/// Derive the SphincsPlusParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The SphincsPlusParameters enumeration member</param>
	///
	/// <returns>The matching SphincsPlusParameters string name</returns>
	static std::string ToName(SphincsPlusParameters Enumeral);

	/// <summary>
	/// Derive the SphincsPlusParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The SphincsPlusParameters string name</param>
	///
	/// <returns>The matching SphincsPlusParameters enumeration type name</returns>
	static SphincsPlusParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
