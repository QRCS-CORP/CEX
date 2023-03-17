#ifndef CEX_MLWEPARAMETERS_H
#define CEX_MLWEPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricParameters.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The Kyber parameter sets enumeration
/// </summary>
enum class KyberParameters : uint8_t
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters; (Low-Medium Security) A modulus of 3329 with 256 coefficients and K of 2
	/// </summary>
	KYBERS1P1632 = static_cast<uint8_t>(AsymmetricParameters::KYBERS1P1632),
	/// <summary>
	/// The S3 parameters; (Medium Security) A modulus of 3329 with 256 coefficients and K of 3
	/// </summary>
	KYBERS3P2400 = static_cast<uint8_t>(AsymmetricParameters::KYBERS3P2400),
	/// <summary>
	/// The S5 parameters; (High Security) A modulus of 3329 with 256 coefficients and K of 4
	/// </summary>
	KYBERS5P3168 = static_cast<uint8_t>(AsymmetricParameters::KYBERS5P3168),
	/// <summary>
	/// The S6 parameters; (Highest Security) A modulus of 3329 with 256 coefficients and K of 5
	/// </summary>
	KYBERS6P3936 = static_cast<uint8_t>(AsymmetricParameters::KYBERS6P3936)
};

class KyberParameterConvert
{
public:

	/// <summary>
	/// Derive the KyberParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The KyberParameters enumeration member</param>
	///
	/// <returns>The matching KyberParameters string name</returns>
	static std::string ToName(KyberParameters Enumeral);

	/// <summary>
	/// Derive the KyberParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The KyberParameters string name</param>
	///
	/// <returns>The matching KyberParameters enumeration type name</returns>
	static KyberParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
