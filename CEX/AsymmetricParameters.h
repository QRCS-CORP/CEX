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
	/// The ECDH S1 parameter; elliptic 25519 curve using the SHA3-512 digest (Keccak)
	/// </summary>
	ECDHS1EC25519K = 5,
	/// <summary>
	/// The ECDH S2 parameter; elliptic 25519 curve using the SHA2-512 digest
	/// </summary>
	ECDHS2EC25519S = 6,
	/// <summary>
	/// The ECDSA S1 parameter; elliptic ED25519 curve using the SHA3-512 digest (Keccak)
	/// </summary>
	ECDSAS1ED25519K = 7,
	/// <summary>
	/// The ECDSA S2 parameter; elliptic ED25519 curve using the SHA2-512 digest
	/// </summary>
	ECDSAS2ED25519S = 8,
	/// <summary>
	/// The Kyber S1 parameters; (Medium Security) A modulus of 7681 with 256 coefficients and K of 2
	/// </summary>
	MLWES1Q3329N256 = 9,
	/// <summary>
	/// The Kyber S2 parameters; (High Security) A modulus of 7681 with 256 coefficients and K of 3
	/// </summary>
	MLWES2Q3329N256 = 10,
	/// <summary>
	/// The Kyber S3 parameters; (Highest Security) A modulus of 7681 with 256 coefficients and K of 4
	/// </summary>
	MLWES3Q3329N256 = 11,
	/// <summary>
	/// The McEliece S2 parameters (Medium-High Security) A finite field of 13 and an error correction capability of 119
	/// </summary>
	MPKCS2N6960T119 = 12,
	/// <summary>
	/// The McEliece S3 parameters (High Security) A finite field of 13 and an error correction capability of 128
	/// </summary>
	MPKCS3N8192T128 = 13,
	/// <summary>
	/// The NTRU-Prime S1 parameters; (Medium Security) The rounded quotient form S-Prime, modulus of 4621 with 653 coefficients
	/// </summary>
	NTRUS1SQ4621N653 = 14,
	/// <summary>
	/// The NTRU-Prime S2 parameters; (High Security) The rounded quotient form S-Prime, modulus of 4591 with 761 coefficients
	/// </summary>
	NTRUS2SQ4591N761 = 15,
	/// <summary>
	/// The NTRU-Prime S3 parameters; (Highest Security) The rounded quotient form S-Prime, modulus of 5167 with 857 coefficients
	/// </summary>
	NTRUS3SQ5167N857 = 16,
	/// <summary>
	/// The Rainbow S1 parameters; (Medium Security) SHA2256, S128 parameter set
	/// </summary>
	RNBWS1S128SHAKE256 = 17,
	/// <summary>
	/// The Rainbow S2 parameters; (High Security) SHA384, S192 parameter set
	/// </summary>
	RNBWS2S192SHAKE512 = 18,
	/// <summary>
	/// The Rainbow S3 parameters; (Highest Security) SHA2512, S256 parameter set
	/// </summary>
	RNBWS3S256SHAKE512 = 19,
	/// <summary>
	/// The NewHope S1 parameters; (High Security) A modulus of 12289 with 1024 coefficients
	/// </summary>
	RLWES1Q12289N1024 = 20,
	/// <summary>
	/// The NewHope S2 parameters; (Highest Security - Experimental) A modulus of 12289 with 2048 coefficients
	/// </summary>
	RLWES2Q12289N2048 = 21,
	/// <summary>
	/// The SphincsPlus S1 parameters; (Medium Security) The SphincsPlus SHAKE256, S128 parameter set
	/// </summary>
	SPXPS1S128SHAKE = 22,
	/// <summary>
	/// The SphincsPlus S2 parameters; (High Security) The SphincsPlus SHAKE256, S192 parameter set
	/// </summary>
	SPXPS2S192SHAKE = 23,
	/// <summary>
	/// The SphincsPlus S3 parameters; (Highest Security) The SphincsPlus SHAKE256, S256 parameter set
	/// </summary>
	SPXPS3S256SHAKE = 24,
	/// <summary>
	/// The XMSS SHA2256H10 parameter; (Medium Security) SHA2-256 with a tree height of 10
	/// </summary>
	XMSSSHA2256H10 = 25,
	/// <summary>
	/// The XMSS SHA2256H16 parameter; (Medium Security) SHA2-256 with a tree height of 16
	/// </summary>
	XMSSSHA2256H16 = 26,
	/// <summary>
	/// The XMSS SHA2256H20 parameter; (Medium Security) The SHA2-256 with a tree height of 20
	/// </summary>
	XMSSSHA2256H20 = 27,
	/// <summary>
	/// The XMSS SHA2512H10 parameter; (High Security) SHA2-512 with a tree height of 10
	/// </summary>
	XMSSSHA2512H10 = 28,
	/// <summary>
	/// The XMSS SHA2512H10 parameter; (High Security) SHA2-512 with a tree height of 16
	/// </summary>
	XMSSSHA2512H16 = 29,
	/// <summary>
	/// The XMSS SHA2512H20 parameter; (Highest Security) SHA2-512 with a tree height of 20
	/// </summary>
	XMSSSHA2512H20 = 30,
	/// <summary>
	/// The XMSS SHAKE256H10 parameter; (Medium Security) SHAKE-256 with a tree height of 10
	/// </summary>
	XMSSSHAKE256H10 = 31,
	/// <summary>
	/// The SHAKE256H16 S1 parameter; (Medium Security) SHAKE-256 with a tree height of 16
	/// </summary>
	XMSSSHAKE256H16 = 32,
	/// <summary>
	/// The XMSS SHAKE256H20 parameter; (Medium Security) SHAKE-256 with a tree height of 20
	/// </summary>
	XMSSSHAKE256H20 = 33,
	/// <summary>
	/// The XMSS SHAKE512H10 parameter; (High Security) SHAKE-512 with a tree height of 10
	/// </summary>
	XMSSSHAKE512H10 = 34,
	/// <summary>
	/// The XMSS SHAKE512H10 parameter; (High Security) SHAKE-512 with a tree height of 16
	/// </summary>
	XMSSSHAKE512H16 = 35,
	/// <summary>
	/// The XMSS SHAKE512H20 parameter; (Highest Security) SHAKE-512 with a tree height of 20
	/// </summary>
	XMSSSHAKE512H20 = 36,
	/// <summary>
	/// The XMSS-MT SHA2256H20D2 parameter; (Medium Security) SHA2-256 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHA2256H20D2 = 37,
	/// <summary>
	/// The XMSS-MT SHA2256H20D4 parameter; (Medium Security) SHA2-256 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHA2256H20D4 = 38,
	/// <summary>
	/// The XMSS-MT SHA2256H40D2 parameter; (Medium Security) SHA2-256 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHA2256H40D2 = 39,
	/// <summary>
	/// The XMSS-MT SHA2256H40D4 parameter; (Medium Security) SHA2-256 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHA2256H40D4 = 40,
	/// <summary>
	/// The XMSS-MT SHA2256H40D8 parameter; (Medium Security) SHA2-256 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHA2256H40D8 = 41,
	/// <summary>
	/// The XMSS-MT SHA2256H60D3 parameter; (Medium Security) SHA2-256 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHA2256H60D3 = 42,
	/// <summary>
	/// The XMSS-MT SHA2256H60D6 parameter; (Medium Security) SHA2-256 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHA2256H60D6 = 43,
	/// <summary>
	/// The XMSS-MT SHA2256H60D12 parameter; (Medium Security) SHA2-256 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHA2256H60D12 = 44,
	/// <summary>
	/// The XMSS-MT SHA2512H20D2 parameter; (High Security) SHA2-512 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHA2512H20D2 = 45,
	/// <summary>
	/// The XMSS-MT SHA2512H20D4 parameter; (High Security) SHA2-512 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHA2512H20D4 = 46,
	/// <summary>
	/// The XMSS-MT SHA2512H40D2 parameter; (High Security) SHA2-512 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHA2512H40D2 = 47,
	/// <summary>
	/// The XMSS-MT SHA2512H40D4 parameter; (High Security) SHA2-512 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHA2512H40D4 = 48,
	/// <summary>
	/// The XMSS-MT SHA2512H40D8 parameter; (High Security) SHA2-512 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHA2512H40D8 = 49,
	/// <summary>
	/// The XMSS-MT SHA2512H60D3 parameter; (Highest Security) SHA2-512 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHA2512H60D3 = 50,
	/// <summary>
	/// The XMSS-MT SHA2512H60D6 parameter; (Highest Security) SHA2-512 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHA2512H60D6 = 51,
	/// <summary>
	/// The XMSS-MT SHA2512H60D12 parameter; (Highest Security) SHA2-512 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHA2512H60D12 = 52,
	/// <summary>
	/// The XMSS-MT SHAKE256H20D2 parameter; (Medium Security) SHAKE-256 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE256H20D2 = 53,
	/// <summary>
	/// The XMSS-MT SHAKE256H20D4 parameter; (Medium Security) SHAKE-256 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE256H20D4 = 54,
	/// <summary>
	/// The XMSS-MT SHAKE256H40D2 parameter; (Medium Security) SHAKE-256 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE256H40D2 = 55,
	/// <summary>
	/// The XMSS-MT SHAKE256H40D4 parameter; (Medium Security) SHAKE-256 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE256H40D4 = 56,
	/// <summary>
	/// The XMSS-MT SHAKE256H40D8 parameter; (Medium Security) SHAKE-256 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHAKE256H40D8 = 57,
	/// <summary>
	/// The XMSS-MT SHAKE256H60D3 parameter; (Medium Security) SHAKE-256 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHAKE256H60D3 = 58,
	/// <summary>
	/// The XMSS-MT SHAKE256H60D6 parameter; (Medium Security) SHAKE-256 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHAKE256H60D6 = 59,
	/// <summary>
	/// The XMSS-MT SHAKE256H60D12 parameter; (Medium Security) SHAKE-256 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHAKE256H60D12 = 60,
	/// <summary>
	/// The XMSS-MT SHAKE512H20D2 parameter; (High Security) SHAKE-512 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE512H20D2 = 61,
	/// <summary>
	/// The XMSS-MT SHAKE512H20D4 parameter; (High Security) SHAKE-512 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE512H20D4 = 62,
	/// <summary>
	/// The XMSS-MT SHAKE512H40D2 parameter; (High Security) SHAKE-512 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE512H40D2 = 63,
	/// <summary>
	/// The XMSS-MT SHA2512H40D4 parameter; (High Security) SHAKE-512 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE512H40D4 = 64,
	/// <summary>
	/// The XMSS-MT SHA2512H40D8 parameter; (High Security) SHAKE-512 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHAKE512H40D8 = 65,
	/// <summary>
	/// The XMSS-MT SHAKE512H60D3 parameter; (Highest Security) SHAKE-512 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHAKE512H60D3 = 66,
	/// <summary>
	/// The XMSS-MT SHAKE512H60D6 parameter; (Highest Security) SHAKE-512 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHAKE512H60D6 = 67,
	/// <summary>
	/// The XMSS-MT SHAKE512H60D12 parameter; (Highest Security) SHAKE-512 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHAKE512H60D12 = 68
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



