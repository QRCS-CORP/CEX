#ifndef CEX_ASYMMETRICTRANSFORMS_H
#define CEX_ASYMMETRICTRANSFORMS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Asymmetric cipher enumeration names
/// </summary>
enum class AsymmetricTransforms : byte
{
	/// <summary>
	/// No asymmetric transform is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters; (Medium Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLMS1256Q8380417 = 1,
	/// <summary>
	/// The S2 parameters; (High Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLMS2N256Q8380417 = 2,
	/// <summary>
	/// The S3 parameters; (Highest Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLMS3N256Q8380417 = 3,
	/// <summary>
	/// The S2 parameters; (Medium Security) A modulus of 7681 with 256 coefficients and K of 2
	/// </summary>
	MLWES2Q7681N256 = 4,
	/// <summary>
	/// The S3 parameters; (High Security) A modulus of 7681 with 256 coefficients and K of 3
	/// </summary>
	MLWES3Q7681N256 = 5,
	/// <summary>
	/// The S4 parameters; (Highest Security) A modulus of 7681 with 256 coefficients and K of 4
	/// </summary>
	MLWES4Q7681N256 = 6,
	/// <summary>
	/// The S1 parameters (Medium Security) A finite field of 12 and an error correction capability of 62
	/// </summary>
	MPKCS1N4096T62 = 7,
	/// <summary>
	/// The S2 parameters (Medium-High Security) A finite field of 13 and an error correction capability of 119
	/// </summary>
	MPKCS1N6960T119 = 8,
	/// <summary>
	/// The S3 parameters (High Security) A finite field of 13 and an error correction capability of 128
	/// </summary>
	MPKCS1N8192T128 = 9,
	/// <summary>
	/// The S1 parameters; (High Security) The rounded product form L-Prime, modulus of 4591 with 761 coefficients
	/// </summary>
	NTRUS1LQ4591N761 = 10,
	/// <summary>
	/// The S2 parameters; (High Security) The rounded quotient form S-Prime, modulus of 4591 with 761 coefficients
	/// </summary>
	NTRUS2SQ4591N761 = 11,
	/// <summary>
	/// The S1 parameters; (High Security) A modulus of 12289 with 1024 coefficients
	/// </summary>
	RLWES1Q12289N1024 = 12,
	/// <summary>
	/// A modulus of 12289 with 2048 coefficients
	/// </summary>
	RLWES2Q12289N2048 = 13,
	/// <summary>
	/// The S1 parameters; (Medium Security) The Sphincs SHAKE128, F256 parameter set
	/// </summary>
	SPXS128F256 = 14,
	/// <summary>
	/// The S2 parameters; (High Security) The Sphincs SHAKE256, F256 parameter set
	/// </summary>
	SPXS256F256 = 15,
	/// <summary>
	/// The S3 parameters; (Highest Security) The experimental Sphincs SHAKE512, F256 parameter set
	/// </summary>
	SPXS512F256 = 16
};

class AsymmetricTransformConvert
{
public:

	/// <summary>
	/// Derive the AsymmetricTransforms formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The AsymmetricTransforms enumeration member</param>
	///
	/// <returns>The matching AsymmetricTransforms string name</returns>
	static std::string ToName(AsymmetricTransforms Enumeral);

	/// <summary>
	/// Derive the AsymmetricTransforms enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The AsymmetricTransforms string name</param>
	///
	/// <returns>The matching AsymmetricTransforms enumeration type name</returns>
	static AsymmetricTransforms FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif



