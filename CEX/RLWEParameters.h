#ifndef CEX_RLWEPARAMETERS_H
#define CEX_RLWEPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricTransforms.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The RingLWE parameter sets enumeration
/// </summary>
enum class RLWEParameters : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters; (High Security) A modulus of 12289 with 1024 coefficients
	/// </summary>
	RLWES1Q12289N1024 = static_cast<byte>(AsymmetricTransforms::RLWES1Q12289N1024),
	/// <summary>
	/// A modulus of 12289 with 2048 coefficients
	/// </summary>
	RLWES2Q12289N2048 = static_cast<byte>(AsymmetricTransforms::RLWES2Q12289N2048)
};

class RLWEParameterConvert
{
public:

	/// <summary>
	/// Derive the RLWEParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The RLWEParameters enumeration member</param>
	///
	/// <returns>The matching RLWEParameters string name</returns>
	static std::string ToName(RLWEParameters Enumeral);

	/// <summary>
	/// Derive the RLWEParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The RLWEParameters string name</param>
	///
	/// <returns>The matching RLWEParameters enumeration type name</returns>
	static RLWEParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
