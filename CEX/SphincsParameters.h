#ifndef CEX_SPHINCSPARAMETERS_H
#define CEX_SPHINCSPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricTransforms.h"

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
	/// The S1 parameters; (Medium Security) The Sphincs SHAKE128, F256 parameter set
	/// </summary>
	SPXS128F256 = static_cast<byte>(AsymmetricTransforms::SPXS128F256),
	/// <summary>
	/// The S2 parameters; (High Security) The Sphincs SHAKE256, F256 parameter set
	/// </summary>
	SPXS256F256 = static_cast<byte>(AsymmetricTransforms::SPXS256F256),
	/// <summary>
	/// The S3 parameters; (Highest Security) The experimental Sphincs SHAKE512, F256 parameter set
	/// </summary>
	SPXS512F256 = static_cast<byte>(AsymmetricTransforms::SPXS512F256)
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
