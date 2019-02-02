#ifndef CEX_DILITHIUMPARAMETERS_H
#define CEX_DILITHIUMPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricTransforms.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The Dilithium parameter sets enumeration
/// </summary>
enum class DilithiumParameters : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters; (Medium Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLMS1256Q8380417 = static_cast<byte>(AsymmetricTransforms::DLMS1256Q8380417),
	/// <summary>
	/// The S2 parameters; (High Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLMS2N256Q8380417 = static_cast<byte>(AsymmetricTransforms::DLMS2N256Q8380417),
	/// <summary>
	/// The S3 parameters; (Highest Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLMS3N256Q8380417 = static_cast<byte>(AsymmetricTransforms::DLMS3N256Q8380417),
};

class DilithiumParameterConvert
{
public:

	/// <summary>
	/// Derive the DilithiumParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The DilithiumParameters enumeration member</param>
	///
	/// <returns>The matching DilithiumParameters string name</returns>
	static std::string ToName(DilithiumParameters Enumeral);

	/// <summary>
	/// Derive the DilithiumParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The DilithiumParameters string name</param>
	///
	/// <returns>The matching DilithiumParameters enumeration type name</returns>
	static DilithiumParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
