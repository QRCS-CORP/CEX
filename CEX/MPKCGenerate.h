#ifndef _CEX_MPKCGENERATE_H
#define _CEX_MPKCGENERATE_H

#include "CexDomain.h"
#include "IDigest.h"
#include "IPrng.h"
#include "MPKCParamSet.h"

NAMESPACE_MCELIECE

/// <summary>
/// 
/// </summary>
class MPKCGenerate
{
public:

	/**
	* \internal
	*/

	void Generate(std::vector<byte> &PubKey, std::vector<byte> &PriKey, Prng::IPrng* Rng, bool Parallel)
	{
		while (1)
		{
			sk_gen2::sk_gen(sk, r);

			if (pk_gen2::pk_gen(pk, sk) == 0)
				break;
		}
	}

private:

};

NAMESPACE_MCELIECEEND
#endif