#ifndef _CEX_FFTQ12289N1024_H
#define _CEX_FFTQ12289N1024_H

#include "CexDomain.h"
#include "IDigest.h"
#include "IPrng.h"

NAMESPACE_RINGLWE

/// <summary>
/// The RingLWE FFT using a modulus of 12289 with 1024 coefficients
/// </summary>
class FFTQ12289N1024
{
public:

	/// <summary>
	/// The number of coefficients
	/// </summary>
	static const uint N = 1024;

	/// <summary>
	/// The modulus factor
	/// </summary>
	static const int Q = 12289;

	/// <summary>
	/// The byte size of A's public key polynomial
	/// </summary>
	static const size_t POLY_BYTES = 1792;

	/// <summary>
	/// The byte size of B's encrypted seed array
	/// </summary>
	static const size_t RECD_BYTES = 256;

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	static const size_t SEED_BYTES = 32;

	/// <summary>
	/// The byte size of A's forward message to host B
	/// </summary>
	static const size_t SENDA_BYTES = POLY_BYTES + SEED_BYTES;

	/// <summary>
	/// The byte size of B's reply message to host A
	/// </summary>
	static const size_t SENDB_BYTES = POLY_BYTES + RECD_BYTES;

	/// <summary>
	/// The parameter sets formal name
	/// </summary>
	static const std::string Name;

	/**
	* \internal
	*/

	static void DecodeA(std::vector<ushort> &Pk, std::vector<byte> &Seed, const std::vector<byte> &R);
	static void DecodeB(std::vector<ushort> &B, std::vector<ushort> &C, const std::vector<byte> &R);
	static void EncodeA(std::vector<byte> &R, const std::vector<ushort> &Pk, const std::vector<byte> &Seed);
	static void EncodeB(std::vector<byte> &R, const std::vector<ushort> &B, const std::vector<ushort> &C);
	static void GenA(std::vector<ushort> &A, const std::vector<byte> &Seed, bool Parallel);
	static void KeyGen(std::vector<byte> &Send, std::vector<ushort> &Sk, Prng::IPrng* Rng, bool Parallel);
	static void SharedA(std::vector<byte> &SharedKey, const std::vector<ushort> &Sk, const std::vector<byte> &Received, Digest::IDigest* Digest);
	static void SharedB(std::vector<byte> &SharedKey, std::vector<byte> &Send, const std::vector<byte> &Received, Prng::IPrng *Rng, Digest::IDigest* Digest, bool Parallel);

private:

	static const uint QINV = 12287;
	static const uint RLOG = 18;
	static const std::vector<ushort> BitrevTable;
	static const std::vector<ushort> OmegasMontgomery;
	static const std::vector<ushort> OmegasInvMontgomery;
	static const std::vector<ushort> PsisBitrevMontgomery;
	static const std::vector<ushort> PsisInvMontgomery;

	static ushort BarrettReduce(ushort A);
	static void BitReverse(std::vector<ushort> &Poly);
	static void FromBytes(std::vector<ushort> &R, const std::vector<byte> &A);
	static void FwdNTT(std::vector<ushort> &A, const std::vector<ushort> &Omega);
	static void HelpRec(std::vector<ushort> &C, const std::vector<ushort> &V, std::vector<byte> &Random);
	static void InvNTT(std::vector<ushort> &R);
	static ushort MontgomeryReduce(uint A);
	static void PolyAdd(std::vector<ushort> &R, const std::vector<ushort> &A, const std::vector<ushort> &B);
	static void PolyGetNoise(std::vector<ushort> &R, std::vector<byte> &Random);
	static void PolyMul(std::vector<ushort> &Poly, const std::vector<ushort> &Factors);
	static void PolyNTT(std::vector<ushort> &R);
	static void PolyPointwise(std::vector<ushort> &R, const std::vector<ushort> &A, const std::vector<ushort> &B);
	static void PolyUniform(std::vector<ushort> &A, const std::vector<byte> &Seed, bool Parallel);
	static void Rec(std::vector<byte> &Key, const std::vector<ushort> &V, const std::vector<ushort> &C);
	static void ToBytes(std::vector<byte> &R, const std::vector<ushort> &Poly);
};

NAMESPACE_RINGLWEEND
#endif