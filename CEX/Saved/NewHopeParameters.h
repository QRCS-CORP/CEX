#ifndef CEX_RLWEPARAMETERS_H
#define CEX_RLWEPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricParameters.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The NewHope parameter sets enumeration
/// </summary>
enum class NewHopeParameters : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters; (High Security) A modulus of 12289 with 1024 coefficients
	/// </summary>
	RLWES1Q12289N1024 = static_cast<byte>(AsymmetricParameters::RLWES1Q12289N1024),
	/// <summary>
	/// A modulus of 12289 with 2048 coefficients
	/// </summary>
	RLWES2Q12289N2048 = static_cast<byte>(AsymmetricParameters::RLWES2Q12289N2048)
};

class NewHopeParameterConvert
{
public:

	/// <summary>
	/// Derive the NewHopeParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The NewHopeParameters enumeration member</param>
	///
	/// <returns>The matching NewHopeParameters string name</returns>
	static std::string ToName(NewHopeParameters Enumeral);

	/// <summary>
	/// Derive the NewHopeParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The NewHopeParameters string name</param>
	///
	/// <returns>The matching NewHopeParameters enumeration type name</returns>
	static NewHopeParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
