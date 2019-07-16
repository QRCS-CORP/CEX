#ifndef CEX_SPHINCSPARAMETERS_H
#define CEX_SPHINCSPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricParameters.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The SPHINCS+ parameter sets enumeration
/// </summary>
enum class SphincsParameters : byte
{
	/// <summary>
	/// No parameter is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters; (Medium Security) The Sphincs SHAKE256, S128 parameter set
	/// </summary>
	SPXS1S128SHAKE = static_cast<byte>(AsymmetricParameters::SPXS1S128SHAKE),
	/// <summary>
	/// The S2 parameters; (High Security) The Sphincs SHAKE256, S192 parameter set
	/// </summary>
	SPXS2S192SHAKE = static_cast<byte>(AsymmetricParameters::SPXS2S192SHAKE),
	/// <summary>
	/// The S3 parameters; (Highest Security) The Sphincs SHAKE256, S256 parameter set
	/// </summary>
	SPXS3S256SHAKE = static_cast<byte>(AsymmetricParameters::SPXS3S256SHAKE)
};

class SphincsParameterConvert
{
public:

	/// <summary>
	/// Derive the SphincsParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The SphincsParameters enumeration member</param>
	///
	/// <returns>The matching SphincsParameters string name</returns>
	static std::string ToName(SphincsParameters Enumeral);

	/// <summary>
	/// Derive the SphincsParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The SphincsParameters string name</param>
	///
	/// <returns>The matching SphincsParameters enumeration type name</returns>
	static SphincsParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
