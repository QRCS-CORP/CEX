#ifndef CEX_NTRUPARAMETERS_H
#define CEX_NTRUPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricTransforms.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The NTRUPrime parameter sets enumeration
/// </summary>
enum class NTRUParameters : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters; (Medium Security) The rounded quotient form S-Prime, modulus of 4621 with 653 coefficients
	/// </summary>
	NTRUS1SQ4621N653 = static_cast<byte>(AsymmetricTransforms::NTRUS1SQ4621N653),
	/// <summary>
	/// The S2 parameters; (High Security) The rounded quotient form S-Prime, modulus of 4591 with 761 coefficients
	/// </summary>
	NTRUS2SQ4591N761 = static_cast<byte>(AsymmetricTransforms::NTRUS2SQ4591N761),
	/// <summary>
	/// The S3 parameters; (Highest Security) The rounded quotient form S-Prime, modulus of 5167 with 857 coefficients
	/// </summary>
	NTRUS3SQ5167N857 = static_cast<byte>(AsymmetricTransforms::NTRUS3SQ5167N857)
};

class NTRUParameterConvert
{
public:

	/// <summary>
	/// Derive the NTRUParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The NTRUParameters enumeration member</param>
	///
	/// <returns>The matching NTRUParameters string name</returns>
	static std::string ToName(NTRUParameters Enumeral);

	/// <summary>
	/// Derive the NTRUParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The NTRUParameters string name</param>
	///
	/// <returns>The matching NTRUParameters enumeration type name</returns>
	static NTRUParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
