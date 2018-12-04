#ifndef CEX_ASYMMETRICENGINES_H
#define CEX_ASYMMETRICTRANSFORMS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Asymmetric cipher enmumeration names
/// </summary>
enum class AsymmetricTransforms : byte
{
	/// <summary>
	/// No asymmetric transform is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// McEliece transform; a finite field of 12 and an error correction capability of 62
	/// </summary>
	MPKCS1M12T62 = 1,
	/// <summary>
	/// McEliece transform; a finite field of 13 and an error correction capability of 119
	/// </summary>
	M13T119 = 2,
	/// <summary>
	/// McEliece transform; a finite field of 13 and an error correction capability of 128
	/// </summary>
	M13T128 = 3,
	/// <summary>
	/// ModuleLWE transform; a modulus of 7681 with 256 coefficients and K of 2
	/// </summary>
	Q7681K2 = 4,
	/// <summary>
	/// ModuleLWE transform; a modulus of 7681 with 256 coefficients and K of 3
	/// </summary>
	Q7681K3 = 5,
	/// <summary>
	/// ModuleLWE transform; a modulus of 7681 with 256 coefficients and K of 4
	/// </summary>
	Q7681K4 = 6,
	/// <summary>
	/// RingLWE transform; a modulus of 12289 with 512 coefficients
	/// </summary>
	Q12289N512 = 7,
	/// <summary>
	/// RingLWE transform; a modulus of 12289 with 1024 coefficients
	/// </summary>
	RLWES1Q12289N1024 = 8,
	/// <summary>
	/// NTRU transform; a modulus of 12289 with W 250
	/// </summary>
	Q4591W250 = 9,
	/// <summary>
	/// NTRU transform; a modulus of 12289 with W 286
	/// </summary>
	Q4591W286 = 10
};

NAMESPACE_ENUMERATIONEND
#endif



