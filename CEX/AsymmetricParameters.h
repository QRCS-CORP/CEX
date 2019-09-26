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
	/// The McEliece S1 parameters (Medium Security) A finite field of 12 and an error correction capability of 62
	/// </summary>
	MPKCS1N4096T62 = 7,
	/// <summary>
	/// The McEliece S2 parameters (Medium-High Security) A finite field of 13 and an error correction capability of 119
	/// </summary>
	MPKCS1N6960T119 = 8,
	/// <summary>
	/// The McEliece S3 parameters (High Security) A finite field of 13 and an error correction capability of 128
	/// </summary>
	MPKCS1N8192T128 = 9,
	/// <summary>
	/// The NTRU-Prime S1 parameters; (Medium Security) The rounded quotient form S-Prime, modulus of 4621 with 653 coefficients
	/// </summary>
	NTRUS1SQ4621N653 = 10,
	/// <summary>
	/// The NTRU-Prime S2 parameters; (High Security) The rounded quotient form S-Prime, modulus of 4591 with 761 coefficients
	/// </summary>
	NTRUS2SQ4591N761 = 11,
	/// <summary>
	/// The NTRU-Prime S3 parameters; (Highest Security) The rounded quotient form S-Prime, modulus of 5167 with 857 coefficients
	/// </summary>
	NTRUS3SQ5167N857 = 12,
	/// <summary>
	/// The Rainbow S1 parameters; (Medium Security) SHA256, S128 parameter set
	/// </summary>
	RNBWS1S128SHAKE256 = 13,
	/// <summary>
	/// The Rainbow S2 parameters; (High Security) SHA384, S192 parameter set
	/// </summary>
	RNBWS2S192SHAKE512 = 14,
	/// <summary>
	/// The Rainbow S3 parameters; (Highest Security) SHA512, S256 parameter set
	/// </summary>
	RNBWS3S256SHAKE512 = 15,
	/// <summary>
	/// The NewHope S1 parameters; (High Security) A modulus of 12289 with 1024 coefficients
	/// </summary>
	RLWES1Q12289N1024 = 16,
	/// <summary>
	/// The NewHope S2 parameters; (Highest Security - Experimental) A modulus of 12289 with 2048 coefficients
	/// </summary>
	RLWES2Q12289N2048 = 17,
	/// <summary>
	/// The SphincsPlus S1 parameters; (Medium Security) The SphincsPlus SHAKE256, S128 parameter set
	/// </summary>
	SPXPS1S128SHAKE = 18,
	/// <summary>
	/// The SphincsPlus S2 parameters; (High Security) The SphincsPlus SHAKE256, S192 parameter set
	/// </summary>
	SPXPS2S192SHAKE = 19,
	/// <summary>
	/// The SphincsPlus S3 parameters; (Highest Security) The SphincsPlus SHAKE256, S256 parameter set
	/// </summary>
	SPXPS3S256SHAKE = 20,
	/// <summary>
	/// The XMSS SHA256H10 parameter; (Medium Security) SHA2-256 with a tree height of 10
	/// </summary>
	XMSSSHA256H10 = 21,
	/// <summary>
	/// The XMSS SHA256H16 parameter; (Medium Security) SHA2-256 with a tree height of 16
	/// </summary>
	XMSSSHA256H16 = 22,
	/// <summary>
	/// The XMSS SHA256H20 parameter; (Medium Security) The SHA2-256 with a tree height of 20
	/// </summary>
	XMSSSHA256H20 = 23,
	/// <summary>
	/// The XMSS SHA512H10 parameter; (High Security) SHA2-512 with a tree height of 10
	/// </summary>
	XMSSSHA512H10 = 24,
	/// <summary>
	/// The XMSS SHA512H10 parameter; (High Security) SHA2-512 with a tree height of 16
	/// </summary>
	XMSSSHA512H16 = 25,
	/// <summary>
	/// The XMSS SHA512H20 parameter; (Highest Security) SHA2-512 with a tree height of 20
	/// </summary>
	XMSSSHA512H20 = 26,
	/// <summary>
	/// The XMSS SHAKE256H10 parameter; (Medium Security) SHAKE-256 with a tree height of 10
	/// </summary>
	XMSSSHAKE256H10 = 27,
	/// <summary>
	/// The SHAKE256H16 S1 parameter; (Medium Security) SHAKE-256 with a tree height of 16
	/// </summary>
	XMSSSHAKE256H16 = 28,
	/// <summary>
	/// The XMSS SHAKE256H20 parameter; (Medium Security) SHAKE-256 with a tree height of 20
	/// </summary>
	XMSSSHAKE256H20 = 29,
	/// <summary>
	/// The XMSS SHAKE512H10 parameter; (High Security) SHAKE-512 with a tree height of 10
	/// </summary>
	XMSSSHAKE512H10 = 30,
	/// <summary>
	/// The XMSS SHAKE512H10 parameter; (High Security) SHAKE-512 with a tree height of 16
	/// </summary>
	XMSSSHAKE512H16 = 31,
	/// <summary>
	/// The XMSS SHAKE512H20 parameter; (Highest Security) SHAKE-512 with a tree height of 20
	/// </summary>
	XMSSSHAKE512H20 = 32,
	/// <summary>
	/// The XMSS-MT SHA256H20D2 parameter; (Medium Security) SHA2-256 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHA256H20D2 = 33,
	/// <summary>
	/// The XMSS-MT SHA256H20D4 parameter; (Medium Security) SHA2-256 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHA256H20D4 = 34,
	/// <summary>
	/// The XMSS-MT SHA256H40D2 parameter; (Medium Security) SHA2-256 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHA256H40D2 = 35,
	/// <summary>
	/// The XMSS-MT SHA256H40D4 parameter; (Medium Security) SHA2-256 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHA256H40D4 = 36,
	/// <summary>
	/// The XMSS-MT SHA256H40D8 parameter; (Medium Security) SHA2-256 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHA256H40D8 = 37,
	/// <summary>
	/// The XMSS-MT SHA256H60D3 parameter; (Medium Security) SHA2-256 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHA256H60D3 = 38,
	/// <summary>
	/// The XMSS-MT SHA256H60D6 parameter; (Medium Security) SHA2-256 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHA256H60D6 = 39,
	/// <summary>
	/// The XMSS-MT SHA256H60D12 parameter; (Medium Security) SHA2-256 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHA256H60D12 = 40,
	/// <summary>
	/// The XMSS-MT SHA512H20D2 parameter; (High Security) SHA2-512 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHA512H20D2 = 41,
	/// <summary>
	/// The XMSS-MT SHA512H20D4 parameter; (High Security) SHA2-512 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHA512H20D4 = 42,
	/// <summary>
	/// The XMSS-MT SHA512H40D2 parameter; (High Security) SHA2-512 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHA512H40D2 = 43,
	/// <summary>
	/// The XMSS-MT SHA512H40D4 parameter; (High Security) SHA2-512 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHA512H40D4 = 44,
	/// <summary>
	/// The XMSS-MT SHA512H40D8 parameter; (High Security) SHA2-512 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHA512H40D8 = 45,
	/// <summary>
	/// The XMSS-MT SHA512H60D3 parameter; (Highest Security) SHA2-512 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHA512H60D3 = 46,
	/// <summary>
	/// The XMSS-MT SHA512H60D6 parameter; (Highest Security) SHA2-512 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHA512H60D6 = 47,
	/// <summary>
	/// The XMSS-MT SHA512H60D12 parameter; (Highest Security) SHA2-512 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHA512H60D12 = 48,
	/// <summary>
	/// The XMSS-MT SHAKE256H20D2 parameter; (Medium Security) SHAKE-256 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE256H20D2 = 49,
	/// <summary>
	/// The XMSS-MT SHAKE256H20D4 parameter; (Medium Security) SHAKE-256 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE256H20D4 = 50,
	/// <summary>
	/// The XMSS-MT SHAKE256H40D2 parameter; (Medium Security) SHAKE-256 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE256H40D2 = 51,
	/// <summary>
	/// The XMSS-MT SHAKE256H40D4 parameter; (Medium Security) SHAKE-256 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE256H40D4 = 52,
	/// <summary>
	/// The XMSS-MT SHAKE256H40D8 parameter; (Medium Security) SHAKE-256 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHAKE256H40D8 = 53,
	/// <summary>
	/// The XMSS-MT SHAKE256H60D3 parameter; (Medium Security) SHAKE-256 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHAKE256H60D3 = 54,
	/// <summary>
	/// The XMSS-MT SHAKE256H60D6 parameter; (Medium Security) SHAKE-256 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHAKE256H60D6 = 55,
	/// <summary>
	/// The XMSS-MT SHAKE256H60D12 parameter; (Medium Security) SHAKE-256 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHAKE256H60D12 = 56,
	/// <summary>
	/// The XMSS-MT SHAKE512H20D2 parameter; (High Security) SHAKE-512 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE512H20D2 = 57,
	/// <summary>
	/// The XMSS-MT SHAKE512H20D4 parameter; (High Security) SHAKE-512 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE512H20D4 = 58,
	/// <summary>
	/// The XMSS-MT SHAKE512H40D2 parameter; (High Security) SHAKE-512 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE512H40D2 = 59,
	/// <summary>
	/// The XMSS-MT SHA512H40D4 parameter; (High Security) SHAKE-512 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE512H40D4 = 60,
	/// <summary>
	/// The XMSS-MT SHA512H40D8 parameter; (High Security) SHAKE-512 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHAKE512H40D8 = 61,
	/// <summary>
	/// The XMSS-MT SHAKE512H60D3 parameter; (Highest Security) SHAKE-512 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHAKE512H60D3 = 62,
	/// <summary>
	/// The XMSS-MT SHAKE512H60D6 parameter; (Highest Security) SHAKE-512 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHAKE512H60D6 = 63,
	/// <summary>
	/// The XMSS-MT SHAKE512H60D12 parameter; (Highest Security) SHAKE-512 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHAKE512H60D12 = 64
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



