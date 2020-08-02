#ifndef CEX_ASYMMETRICPARAMETERS_H
#define CEX_ASYMMETRICPARAMETERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Asymmetric cipher and signature-scheme parameter-set names
/// </summary>
enum class AsymmetricParameters : byte
{
	/// <summary>
	/// No asymmetric transform is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The Dilithium S1 parameters; (Medium Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLTMS1N256Q8380417 = 1,
	/// <summary>
	/// The Dilithium S2 parameters; (High Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLTMS2N256Q8380417 = 2,
	/// <summary>
	/// The Dilithium S3 parameters; (Highest Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLTMS3N256Q8380417 = 3,
	/// <summary>
	/// The Kyber S1 parameters; (Medium Security) A modulus of 7681 with 256 coefficients and K of 2
	/// </summary>
	MLWES1Q3329N256 = 4,
	/// <summary>
	/// The Kyber S2 parameters; (High Security) A modulus of 7681 with 256 coefficients and K of 3
	/// </summary>
	MLWES2Q3329N256 = 5,
	/// <summary>
	/// The Kyber S3 parameters; (Highest Security) A modulus of 7681 with 256 coefficients and K of 4
	/// </summary>
	MLWES3Q3329N256 = 6,
	/// <summary>
	/// The McEliece S2 parameters (Medium-High Security) A finite field of 13 and an error correction capability of 119
	/// </summary>
	MPKCS2N6960T119 = 7,
	/// <summary>
	/// The McEliece S3 parameters (High Security) A finite field of 13 and an error correction capability of 128
	/// </summary>
	MPKCS3N8192T128 = 8,
	/// <summary>
	/// The NTRU-Prime S1 parameters; (Medium Security) The rounded quotient form S-Prime, modulus of 4621 with 653 coefficients
	/// </summary>
	NTRUS1SQ4621N653 = 9,
	/// <summary>
	/// The NTRU-Prime S2 parameters; (High Security) The rounded quotient form S-Prime, modulus of 4591 with 761 coefficients
	/// </summary>
	NTRUS2SQ4591N761 = 10,
	/// <summary>
	/// The NTRU-Prime S3 parameters; (Highest Security) The rounded quotient form S-Prime, modulus of 5167 with 857 coefficients
	/// </summary>
	NTRUS3SQ5167N857 = 11,
	/// <summary>
	/// The Rainbow S1 parameters; (Medium Security) SHA2256, S128 parameter set
	/// </summary>
	RNBWS1S128SHAKE256 = 12,
	/// <summary>
	/// The Rainbow S2 parameters; (High Security) SHA384, S192 parameter set
	/// </summary>
	RNBWS2S192SHAKE512 = 13,
	/// <summary>
	/// The Rainbow S3 parameters; (Highest Security) SHA2512, S256 parameter set
	/// </summary>
	RNBWS3S256SHAKE512 = 14,
	/// <summary>
	/// The NewHope S1 parameters; (High Security) A modulus of 12289 with 1024 coefficients
	/// </summary>
	RLWES1Q12289N1024 = 15,
	/// <summary>
	/// The NewHope S2 parameters; (Highest Security - Experimental) A modulus of 12289 with 2048 coefficients
	/// </summary>
	RLWES2Q12289N2048 = 16,
	/// <summary>
	/// The SphincsPlus S1 parameters; (Medium Security) The SphincsPlus SHAKE256, S128 parameter set
	/// </summary>
	SPXPS1S128SHAKE = 17,
	/// <summary>
	/// The SphincsPlus S2 parameters; (High Security) The SphincsPlus SHAKE256, S192 parameter set
	/// </summary>
	SPXPS2S192SHAKE = 18,
	/// <summary>
	/// The SphincsPlus S3 parameters; (Highest Security) The SphincsPlus SHAKE256, S256 parameter set
	/// </summary>
	SPXPS3S256SHAKE = 19,
	/// <summary>
	/// The XMSS SHA2256H10 parameter; (Medium Security) SHA2-256 with a tree height of 10
	/// </summary>
	XMSSSHA2256H10 = 20,
	/// <summary>
	/// The XMSS SHA2256H16 parameter; (Medium Security) SHA2-256 with a tree height of 16
	/// </summary>
	XMSSSHA2256H16 = 21,
	/// <summary>
	/// The XMSS SHA2256H20 parameter; (Medium Security) The SHA2-256 with a tree height of 20
	/// </summary>
	XMSSSHA2256H20 = 22,
	/// <summary>
	/// The XMSS SHA2512H10 parameter; (High Security) SHA2-512 with a tree height of 10
	/// </summary>
	XMSSSHA2512H10 = 23,
	/// <summary>
	/// The XMSS SHA2512H10 parameter; (High Security) SHA2-512 with a tree height of 16
	/// </summary>
	XMSSSHA2512H16 = 24,
	/// <summary>
	/// The XMSS SHA2512H20 parameter; (Highest Security) SHA2-512 with a tree height of 20
	/// </summary>
	XMSSSHA2512H20 = 25,
	/// <summary>
	/// The XMSS SHAKE256H10 parameter; (Medium Security) SHAKE-256 with a tree height of 10
	/// </summary>
	XMSSSHAKE256H10 = 26,
	/// <summary>
	/// The SHAKE256H16 S1 parameter; (Medium Security) SHAKE-256 with a tree height of 16
	/// </summary>
	XMSSSHAKE256H16 = 27,
	/// <summary>
	/// The XMSS SHAKE256H20 parameter; (Medium Security) SHAKE-256 with a tree height of 20
	/// </summary>
	XMSSSHAKE256H20 = 28,
	/// <summary>
	/// The XMSS SHAKE512H10 parameter; (High Security) SHAKE-512 with a tree height of 10
	/// </summary>
	XMSSSHAKE512H10 = 29,
	/// <summary>
	/// The XMSS SHAKE512H10 parameter; (High Security) SHAKE-512 with a tree height of 16
	/// </summary>
	XMSSSHAKE512H16 = 30,
	/// <summary>
	/// The XMSS SHAKE512H20 parameter; (Highest Security) SHAKE-512 with a tree height of 20
	/// </summary>
	XMSSSHAKE512H20 = 31,
	/// <summary>
	/// The XMSS-MT SHA2256H20D2 parameter; (Medium Security) SHA2-256 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHA2256H20D2 = 32,
	/// <summary>
	/// The XMSS-MT SHA2256H20D4 parameter; (Medium Security) SHA2-256 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHA2256H20D4 = 33,
	/// <summary>
	/// The XMSS-MT SHA2256H40D2 parameter; (Medium Security) SHA2-256 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHA2256H40D2 = 34,
	/// <summary>
	/// The XMSS-MT SHA2256H40D4 parameter; (Medium Security) SHA2-256 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHA2256H40D4 = 35,
	/// <summary>
	/// The XMSS-MT SHA2256H40D8 parameter; (Medium Security) SHA2-256 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHA2256H40D8 = 36,
	/// <summary>
	/// The XMSS-MT SHA2256H60D3 parameter; (Medium Security) SHA2-256 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHA2256H60D3 = 37,
	/// <summary>
	/// The XMSS-MT SHA2256H60D6 parameter; (Medium Security) SHA2-256 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHA2256H60D6 = 38,
	/// <summary>
	/// The XMSS-MT SHA2256H60D12 parameter; (Medium Security) SHA2-256 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHA2256H60D12 = 39,
	/// <summary>
	/// The XMSS-MT SHA2512H20D2 parameter; (High Security) SHA2-512 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHA2512H20D2 = 40,
	/// <summary>
	/// The XMSS-MT SHA2512H20D4 parameter; (High Security) SHA2-512 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHA2512H20D4 = 41,
	/// <summary>
	/// The XMSS-MT SHA2512H40D2 parameter; (High Security) SHA2-512 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHA2512H40D2 = 42,
	/// <summary>
	/// The XMSS-MT SHA2512H40D4 parameter; (High Security) SHA2-512 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHA2512H40D4 = 43,
	/// <summary>
	/// The XMSS-MT SHA2512H40D8 parameter; (High Security) SHA2-512 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHA2512H40D8 = 44,
	/// <summary>
	/// The XMSS-MT SHA2512H60D3 parameter; (Highest Security) SHA2-512 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHA2512H60D3 = 45,
	/// <summary>
	/// The XMSS-MT SHA2512H60D6 parameter; (Highest Security) SHA2-512 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHA2512H60D6 = 46,
	/// <summary>
	/// The XMSS-MT SHA2512H60D12 parameter; (Highest Security) SHA2-512 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHA2512H60D12 = 47,
	/// <summary>
	/// The XMSS-MT SHAKE256H20D2 parameter; (Medium Security) SHAKE-256 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE256H20D2 = 48,
	/// <summary>
	/// The XMSS-MT SHAKE256H20D4 parameter; (Medium Security) SHAKE-256 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE256H20D4 = 49,
	/// <summary>
	/// The XMSS-MT SHAKE256H40D2 parameter; (Medium Security) SHAKE-256 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE256H40D2 = 50,
	/// <summary>
	/// The XMSS-MT SHAKE256H40D4 parameter; (Medium Security) SHAKE-256 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE256H40D4 = 51,
	/// <summary>
	/// The XMSS-MT SHAKE256H40D8 parameter; (Medium Security) SHAKE-256 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHAKE256H40D8 = 52,
	/// <summary>
	/// The XMSS-MT SHAKE256H60D3 parameter; (Medium Security) SHAKE-256 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHAKE256H60D3 = 53,
	/// <summary>
	/// The XMSS-MT SHAKE256H60D6 parameter; (Medium Security) SHAKE-256 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHAKE256H60D6 = 54,
	/// <summary>
	/// The XMSS-MT SHAKE256H60D12 parameter; (Medium Security) SHAKE-256 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHAKE256H60D12 = 55,
	/// <summary>
	/// The XMSS-MT SHAKE512H20D2 parameter; (High Security) SHAKE-512 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE512H20D2 = 56,
	/// <summary>
	/// The XMSS-MT SHAKE512H20D4 parameter; (High Security) SHAKE-512 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE512H20D4 = 57,
	/// <summary>
	/// The XMSS-MT SHAKE512H40D2 parameter; (High Security) SHAKE-512 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE512H40D2 = 58,
	/// <summary>
	/// The XMSS-MT SHA2512H40D4 parameter; (High Security) SHAKE-512 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE512H40D4 = 59,
	/// <summary>
	/// The XMSS-MT SHA2512H40D8 parameter; (High Security) SHAKE-512 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHAKE512H40D8 = 60,
	/// <summary>
	/// The XMSS-MT SHAKE512H60D3 parameter; (Highest Security) SHAKE-512 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHAKE512H60D3 = 61,
	/// <summary>
	/// The XMSS-MT SHAKE512H60D6 parameter; (Highest Security) SHAKE-512 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHAKE512H60D6 = 62,
	/// <summary>
	/// The XMSS-MT SHAKE512H60D12 parameter; (Highest Security) SHAKE-512 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHAKE512H60D12 = 63
};

class AsymmetricTransformConvert
{
public:

	/// <summary>
	/// Derive the AsymmetricParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The AsymmetricParameters enumeration member</param>
	///
	/// <returns>The matching AsymmetricParameters string name</returns>
	static std::string ToName(AsymmetricParameters Enumeral);

	/// <summary>
	/// Derive the AsymmetricParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The AsymmetricParameters string name</param>
	///
	/// <returns>The matching AsymmetricParameters enumeration type name</returns>
	static AsymmetricParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif



