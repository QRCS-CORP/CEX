#ifndef CEX_ASYMMETRICPARAMETERS_H
#define CEX_ASYMMETRICPARAMETERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Asymmetric cipher and signature-scheme parameter-set names
/// </summary>
enum class AsymmetricParameters : uint8_t
{
	/// <summary>
	/// No asymmetric cipher or signature scheme is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The Dilithium S1 parameters (Medium Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLTMS1P2544 = 1,
	/// <summary>
	/// The Dilithium S2 parameters (High Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLTMS3P4016 = 2,
	/// <summary>
	/// The Dilithium S3 parameters (Highest Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLTMS5P4880 = 3,
	/// <summary>
	/// The ECDH S1 parameters elliptic 25519 curve using the SHA3-512 digest (Keccak)
	/// </summary>
	ECDHS1EC25519K = 5,
	/// <summary>
	/// The ECDH S2 parameters elliptic 25519 curve using the SHA2-512 digest
	/// </summary>
	ECDHS2EC25519S = 6,
	/// <summary>
	/// The ECDSA S1 parameters elliptic ED25519 curve using the SHA3-512 digest (Keccak)
	/// </summary>
	ECDSAS1ED25519K = 7,
	/// <summary>
	/// The ECDSA S2 parameters elliptic ED25519 curve using the SHA2-512 digest
	/// </summary>
	ECDSAS2ED25519S = 8,
	/// <summary>
	/// The Kyber S1 parameters (Medium Security) A modulus of 7681 with 256 coefficients and K of 2
	/// </summary>
	KYBERS32400 = 9,
	/// <summary>
	/// The Kyber S2 parameters (High Security) A modulus of 7681 with 256 coefficients and K of 3
	/// </summary>
	KYBERS53168 = 10,
	/// <summary>
	/// The Kyber S3 parameters (Highest Security) A modulus of 7681 with 256 coefficients and K of 4
	/// </summary>
	KYBERS63936 = 11,
	/// <summary>
	/// The McEliece S3 parameters (Medium-High Security) A finite field of 13 and an error correction capability of 96
	/// </summary>
	MPKCS3N4608T96 = 12,
	/// <summary>
	/// The McEliece S3 parameters (Medium-High Security) A finite field of 13 and an error correction capability of 119
	/// </summary>
	MPKCS3N6960T119 = 13,
	/// <summary>
	/// The McEliece S4 parameters (High Security) A finite field of 13 and an error correction capability of 128
	/// </summary>
	MPKCS4N6688T128 = 14,
	/// <summary>
	/// The McEliece S5 parameters (High Security) A finite field of 13 and an error correction capability of 128
	/// </summary>
	MPKCS5N8192T128 = 15,
	/// <summary>
	/// The SphincsPlus S1 parameters (Medium Security) The SphincsPlus SHAKE256, S128 parameter set
	/// </summary>
	SPXPS1S128SHAKE = 16,
	/// <summary>
	/// The SphincsPlus S3 parameters (High Security) The SphincsPlus SHAKE256, S192 parameter set
	/// </summary>
	SPXPS3S192SHAKE = 17,
	/// <summary>
	/// The SphincsPlus S5 parameters (Highest Security) The SphincsPlus SHAKE256, S256 parameter set
	/// </summary>
	SPXPS5S256SHAKE = 18,
	/// <summary>
	/// The SphincsPlus S6 parameters (Highest Security) The SphincsPlus SHAKE512, S512 parameter set
	/// </summary>
	SPXPS6S512SHAKE = 19,
	/// <summary>
	/// The XMSS SHA2256H10 parameters (Medium Security) SHA2-256 with a tree height of 10
	/// </summary>
	XMSSSHA2256H10 = 20,
	/// <summary>
	/// The XMSS SHA2256H16 parameters (Medium Security) SHA2-256 with a tree height of 16
	/// </summary>
	XMSSSHA2256H16 = 21,
	/// <summary>
	/// The XMSS SHA2256H20 parameters (Medium Security) The SHA2-256 with a tree height of 20
	/// </summary>
	XMSSSHA2256H20 = 22,
	/// <summary>
	/// The XMSS SHA2512H10 parameters (High Security) SHA2-512 with a tree height of 10
	/// </summary>
	XMSSSHA2512H10 = 23,
	/// <summary>
	/// The XMSS SHA2512H10 parameters (High Security) SHA2-512 with a tree height of 16
	/// </summary>
	XMSSSHA2512H16 = 24,
	/// <summary>
	/// The XMSS SHA2512H20 parameters (Highest Security) SHA2-512 with a tree height of 20
	/// </summary>
	XMSSSHA2512H20 = 25,
	/// <summary>
	/// The XMSS SHAKE256H10 parameters (Medium Security) SHAKE-256 with a tree height of 10
	/// </summary>
	XMSSSHAKE256H10 = 26,
	/// <summary>
	/// The SHAKE256H16 S1 parameters (Medium Security) SHAKE-256 with a tree height of 16
	/// </summary>
	XMSSSHAKE256H16 = 27,
	/// <summary>
	/// The XMSS SHAKE256H20 parameters (Medium Security) SHAKE-256 with a tree height of 20
	/// </summary>
	XMSSSHAKE256H20 = 28,
	/// <summary>
	/// The XMSS SHAKE512H10 parameters (High Security) SHAKE-512 with a tree height of 10
	/// </summary>
	XMSSSHAKE512H10 = 29,
	/// <summary>
	/// The XMSS SHAKE512H10 parameters (High Security) SHAKE-512 with a tree height of 16
	/// </summary>
	XMSSSHAKE512H16 = 30,
	/// <summary>
	/// The XMSS SHAKE512H20 parameters (Highest Security) SHAKE-512 with a tree height of 20
	/// </summary>
	XMSSSHAKE512H20 = 31,
	/// <summary>
	/// The XMSS-MT SHA2256H20D2 parameters (Medium Security) SHA2-256 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHA2256H20D2 = 32,
	/// <summary>
	/// The XMSS-MT SHA2256H20D4 parameters (Medium Security) SHA2-256 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHA2256H20D4 = 33,
	/// <summary>
	/// The XMSS-MT SHA2256H40D2 parameters (Medium Security) SHA2-256 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHA2256H40D2 = 34,
	/// <summary>
	/// The XMSS-MT SHA2256H40D4 parameters (Medium Security) SHA2-256 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHA2256H40D4 = 35,
	/// <summary>
	/// The XMSS-MT SHA2256H40D8 parameters (Medium Security) SHA2-256 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHA2256H40D8 = 36,
	/// <summary>
	/// The XMSS-MT SHA2256H60D3 parameters (Medium Security) SHA2-256 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHA2256H60D3 = 37,
	/// <summary>
	/// The XMSS-MT SHA2256H60D6 parameters (Medium Security) SHA2-256 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHA2256H60D6 = 38,
	/// <summary>
	/// The XMSS-MT SHA2256H60D12 parameters (Medium Security) SHA2-256 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHA2256H60D12 = 39,
	/// <summary>
	/// The XMSS-MT SHA2512H20D2 parameters (High Security) SHA2-512 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHA2512H20D2 = 40,
	/// <summary>
	/// The XMSS-MT SHA2512H20D4 parameters (High Security) SHA2-512 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHA2512H20D4 = 41,
	/// <summary>
	/// The XMSS-MT SHA2512H40D2 parameters (High Security) SHA2-512 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHA2512H40D2 = 42,
	/// <summary>
	/// The XMSS-MT SHA2512H40D4 parameters (High Security) SHA2-512 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHA2512H40D4 = 43,
	/// <summary>
	/// The XMSS-MT SHA2512H40D8 parameters (High Security) SHA2-512 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHA2512H40D8 = 44,
	/// <summary>
	/// The XMSS-MT SHA2512H60D3 parameters (Highest Security) SHA2-512 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHA2512H60D3 = 45,
	/// <summary>
	/// The XMSS-MT SHA2512H60D6 parameters (Highest Security) SHA2-512 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHA2512H60D6 = 46,
	/// <summary>
	/// The XMSS-MT SHA2512H60D12 parameters (Highest Security) SHA2-512 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHA2512H60D12 = 47,
	/// <summary>
	/// The XMSS-MT SHAKE256H20D2 parameters (Medium Security) SHAKE-256 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE256H20D2 = 48,
	/// <summary>
	/// The XMSS-MT SHAKE256H20D4 parameters (Medium Security) SHAKE-256 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE256H20D4 = 49,
	/// <summary>
	/// The XMSS-MT SHAKE256H40D2 parameters (Medium Security) SHAKE-256 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE256H40D2 = 50,
	/// <summary>
	/// The XMSS-MT SHAKE256H40D4 parameters (Medium Security) SHAKE-256 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE256H40D4 = 51,
	/// <summary>
	/// The XMSS-MT SHAKE256H40D8 parameters (Medium Security) SHAKE-256 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHAKE256H40D8 = 52,
	/// <summary>
	/// The XMSS-MT SHAKE256H60D3 parameters (Medium Security) SHAKE-256 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHAKE256H60D3 = 53,
	/// <summary>
	/// The XMSS-MT SHAKE256H60D6 parameters (Medium Security) SHAKE-256 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHAKE256H60D6 = 54,
	/// <summary>
	/// The XMSS-MT SHAKE256H60D12 parameters (Medium Security) SHAKE-256 with a tree height of 60, and 12 subtree layers
	/// </summary>
	XMSSMTSHAKE256H60D12 = 55,
	/// <summary>
	/// The XMSS-MT SHAKE512H20D2 parameters (High Security) SHAKE-512 with a tree height of 20, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE512H20D2 = 56,
	/// <summary>
	/// The XMSS-MT SHAKE512H20D4 parameters (High Security) SHAKE-512 with a tree height of 20, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE512H20D4 = 57,
	/// <summary>
	/// The XMSS-MT SHAKE512H40D2 parameters (High Security) SHAKE-512 with a tree height of 40, and 2 subtree layers
	/// </summary>
	XMSSMTSHAKE512H40D2 = 58,
	/// <summary>
	/// The XMSS-MT SHA2512H40D4 parameters (High Security) SHAKE-512 with a tree height of 40, and 4 subtree layers
	/// </summary>
	XMSSMTSHAKE512H40D4 = 59,
	/// <summary>
	/// The XMSS-MT SHA2512H40D8 parameters (High Security) SHAKE-512 with a tree height of 40, and 8 subtree layers
	/// </summary>
	XMSSMTSHAKE512H40D8 = 60,
	/// <summary>
	/// The XMSS-MT SHAKE512H60D3 parameters (Highest Security) SHAKE-512 with a tree height of 60, and 3 subtree layers
	/// </summary>
	XMSSMTSHAKE512H60D3 = 61,
	/// <summary>
	/// The XMSS-MT SHAKE512H60D6 parameters (Highest Security) SHAKE-512 with a tree height of 60, and 6 subtree layers
	/// </summary>
	XMSSMTSHAKE512H60D6 = 62,
	/// <summary>
	/// The XMSS-MT SHAKE512H60D12 parameters (Highest Security) SHAKE-512 with a tree height of 60, and 12 subtree layers
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



