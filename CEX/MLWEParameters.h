#ifndef CEX_MLWEPARAMETERS_H
#define CEX_MLWEPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricTransforms.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The ModuleLWE parameter sets enumeration
/// </summary>
enum class MLWEParameters : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S2 parameters; (Medium Security) A modulus of 7681 with 256 coefficients and K of 2
	/// </summary>
	MLWES2Q7681N256 = static_cast<byte>(AsymmetricTransforms::MLWES2Q7681N256),
	/// <summary>
	/// The S3 parameters; (High Security) A modulus of 7681 with 256 coefficients and K of 3
	/// </summary>
	MLWES3Q7681N256 = static_cast<byte>(AsymmetricTransforms::MLWES3Q7681N256),
	/// <summary>
	/// The S4 parameters; (Highest Security) A modulus of 7681 with 256 coefficients and K of 4
	/// </summary>
	MLWES4Q7681N256 = static_cast<byte>(AsymmetricTransforms::MLWES4Q7681N256)
};

class MLWEParameterConvert
{
public:

	/// <summary>
	/// Derive the MLWEParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The MLWEParameters enumeration member</param>
	///
	/// <returns>The matching MLWEParameters string name</returns>
	static std::string ToName(MLWEParameters Enumeral);

	/// <summary>
	/// Derive the MLWEParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The MLWEParameters string name</param>
	///
	/// <returns>The matching MLWEParameters enumeration type name</returns>
	static MLWEParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
