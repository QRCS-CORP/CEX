#ifndef CEX_DLIN256Q8380417_H
#define CEX_DLIN256Q8380417_H

#include "CexConfig.h"
#include "DilithiumParameters.h"
#include "IPrng.h"
#include "MemoryTools.h"
#include "SecureRandom.h"
#include "SHAKE.h"

NAMESPACE_DILITHIUM

using Enumeration::DilithiumParameters;
using Kdf::SHAKE;
using Utility::IntegerTools;
using Utility::MemoryTools;

/// <summary>
/// The Dilithium support class
/// </summary>
class DLMN256Q8380417
{
private:

	static const uint DLM_SEED_SIZE = 32UL;
	static const uint DLM_CHR_SIZE = 48UL;
	static const uint DLM_N = 256UL;
	static const uint DLM_Q = 8380417UL;
	static const uint DLM_QBITS = 23UL;
	static const uint DLM_UNITY_ROOT = 1753UL;
	static const uint DLM_D = 14UL;
	static const uint DLM_GAMMA1 = ((DLM_Q - 1U) / 16U);
	static const uint DLM_GAMMA2 = (DLM_GAMMA1 / 2U);
	static const uint DLM_ALPHA = (2U * DLM_GAMMA2);
	static const uint DLM_POL_PACKED = ((DLM_N * DLM_QBITS) / 8);
	static const uint DLM_POLT1_PACKED = ((DLM_N * (DLM_QBITS - DLM_D)) / 8);
	static const uint DLM_POLT0_PACKED = ((DLM_N * DLM_D) / 8);
	static const uint DLM_POLZ_PACKED = ((DLM_N * (DLM_QBITS - 3)) / 8);
	static const uint DLM_POLW1_PACKED = ((DLM_N * 4) / 8);
	// 2^32 % q
	static const uint DLM_MONT = 4193792UL;
	// -q^(-1) mod 2^32
	static const uint DLM_QINV = 4236238847UL;

public:

	class DlmParams
	{
	public:

		size_t PolEtaPack;
		size_t PublicKeySize;
		size_t PrivateKeySize;
		size_t SignatureSize;
		size_t K;
		size_t L;
		uint Eta;
		uint SetABits;
		uint Beta;
		uint Omega;

		DlmParams(DilithiumParameters ParamType)
		{
			switch (ParamType)
			{
				case DilithiumParameters::DLMS1256Q8380417:
				{
					K = 4U;
					L = 3U;
					Eta = 6U;
					SetABits = 4U;
					Beta = 325U;
					Omega = 80U;
					break;
				}
				case DilithiumParameters::DLMS2N256Q8380417:
				{
					K = 5U;
					L = 4U;
					Eta = 5U;
					SetABits = 4U;
					Beta = 275U;
					Omega = 96U;
					break;
				}
				default:
				{
					// DLMS3N256Q8380417
					K = 6U;
					L = 5U;
					Eta = 3U;
					SetABits = 3U;
					Beta = 175U;
					Omega = 120U;
				}
			}

			PolEtaPack = ((DLM_N * SetABits) / 8);
			PublicKeySize = (DLM_SEED_SIZE + K * DLM_POLT1_PACKED);
			PrivateKeySize = (2 * DLM_SEED_SIZE + (L + K) * PolEtaPack + DLM_CHR_SIZE + K * DLM_POLT0_PACKED);
			SignatureSize = (L * DLM_POLZ_PACKED + (Omega + K) + (DLM_N / 8 + 8));
		}

		~DlmParams()
		{
			PolEtaPack = 0;
			PublicKeySize = 0;
			PrivateKeySize = 0;
			SignatureSize = 0;
			K = 0;
			L = 0;
			Eta = 0;
			SetABits = 0;
			Beta = 0;
			Omega = 0;
		}
	};

private:

	typedef struct
	{
		std::array<uint, DLM_N> coeffs;
	} Poly;

	struct PolyVec
	{
	public:

		std::vector<Poly> vec;

		PolyVec()
			:
			vec(0)
		{
		}

		PolyVec(size_t Dimension)
			:
			vec(Dimension)
		{
		}

		~PolyVec()
		{
			IntegerTools::Clear(vec);
		}

		const size_t size()
		{
			return vec.size();
		}
	};

	static const std::vector<uint> Zetas;
	static const std::vector<uint> ZetasInv;

	template<typename Vector>
	inline static void PolyVecAdd(Vector &W, const Vector &U, const Vector &V)
	{
		size_t i;

		for (i = 0; i < V.vec.size(); ++i)
		{
			PolyAdd(W.vec[i], U.vec[i], V.vec[i]);
		}
	}

	template<typename Vector>
	inline static int32_t PolyVecChkNorm(const Vector &V, uint Bound)
	{
		size_t i;
		int32_t ret;

		ret = 0;

		for (i = 0; i < V.vec.size(); ++i)
		{
			ret |= PolyChkNorm(V.vec[i], Bound);
		}

		return ret;
	}

	template<typename Vector>
	inline static void PolyVecCSubq(Vector &V)
	{
		size_t i;

		for (i = 0; i < V.vec.size(); ++i)
		{
			PolyCSubq(V.vec[i]);
		}
	}

	template<typename Vector>
	inline static void PolyVecDecompose(Vector &V1, Vector &V0, const Vector &V)
	{
		size_t i;

		for (i = 0; i < V.vec.size(); ++i)
		{
			PolyDecompose(V1.vec[i], V0.vec[i], V.vec[i]);
		}
	}

	template<typename Vector>
	inline static void PolyVecFreeze(Vector &V)
	{
		size_t i;

		for (i = 0; i < V.vec.size(); ++i)
		{
			PolyFreeze(V.vec[i]);
		}
	}

	template<typename Vector>
	inline static void PolyVecInvNttMontgomery(Vector &V)
	{
		size_t i;

		for (i = 0; i < V.vec.size(); ++i)
		{
			PolyInvNttMontgomery(V.vec[i]);
		}
	}

	template<typename Vector>
	inline static uint PolyVecMakeHint(Vector &H, const Vector &U, const Vector &V)
	{
		size_t i;
		uint s;

		s = 0;

		for (i = 0; i < V.vec.size(); ++i)
		{
			s += PolyMakeHint(H.vec[i], U.vec[i], V.vec[i]);
		}

		return s;
	}

	template<typename Vector>
	inline static void PolyVecNtt(Vector &V)
	{
		size_t i;

		for (i = 0; i < V.vec.size(); ++i)
		{
			Ntt(V.vec[i]);
		}
	}

	template<typename Vector>
	inline static void PolyVecPower2Round(Vector &V1, Vector &V0, const Vector &V)
	{
		size_t i;

		for (i = 0; i < V.vec.size(); ++i)
		{
			PolyPower2Round(V1.vec[i], V0.vec[i], V.vec[i]);
		}
	}

	template<typename Vector>
	inline static void PolyVecPointwiseAccInvMontgomery(Poly &W, const Vector &U, const Vector &V)
	{
		Poly t;
		size_t i;

		PolyPointwiseInvMontgomery(W, U.vec[0], V.vec[0]);

		for (i = 1; i < V.vec.size(); ++i)
		{
			PolyPointwiseInvMontgomery(t, U.vec[i], V.vec[i]);
			PolyAdd(W, W, t);
		}
	}

	template<typename Vector>
	inline static void PolyVecReduce(Vector &V)
	{
		size_t i;

		for (i = 0; i < V.vec.size(); ++i)
		{
			PolyReduce(V.vec[i]);
		}
	}

	template<typename Vector>
	inline static void PolyVecShiftL(Vector &V, uint Shift)
	{
		size_t i;

		for (i = 0; i < V.vec.size(); ++i)
		{
			PolyShiftL(V.vec[i], Shift);
		}
	}

	template<typename Vector>
	inline static void PolyVecSub(Vector &W, const Vector &U, const Vector &V)
	{
		size_t i;

		for (i = 0; i < V.vec.size(); ++i)
		{
			PolySub(W.vec[i], U.vec[i], V.vec[i]);
		}
	}

	template<typename Vector>
	inline static void PolyVecUseHint(Vector &W, const Vector &U, const Vector &H)
	{
		size_t i;

		for (i = 0; i < H.vec.size(); ++i)
		{
			PolyUseHint(W.vec[i], U.vec[i], H.vec[i]);
		}
	}

	static void Absorb(const std::vector<byte> &Input, std::array<ulong, 25> &State);

	static void Challenge(Poly &C, const std::vector<byte> &Mu, const PolyVec &W1);

	static uint CSubQ(uint A);

	static uint Decompose(uint A, uint &A0);

	static void ExpandMatrix(std::vector<PolyVec> &Mat, const std::vector<byte> &Rho);

	static uint Freeze(uint A);

	static void InvNttFromInvMont(std::array<uint, DLM_N> &P);

	static uint MakeHint(uint A, const uint B);

	static uint MontgomeryReduce(ulong A);

	static void Ntt(Poly &P);

	static void PackPk(std::vector<byte> &Pk, const std::vector<byte> Rho, const PolyVec &T1);

	static void PackSig(std::vector<byte> &Signature, const PolyVec &Z, const PolyVec &H, const Poly &C, uint Omega);

	static void PackSk(std::vector<byte> &Sk, const std::vector<byte> &Rho, const std::vector<byte> &Key, const std::vector<byte> &Tr, const PolyVec &S1, const PolyVec &S2, const PolyVec &T0, uint Eta, size_t EtaPack);

	static void PolyAdd(Poly &C, const Poly &A, const Poly &B);

	static int32_t PolyChkNorm(const Poly &A, uint B);

	static void PolyCSubq(Poly &A);

	static void PolyDecompose(Poly &A1, Poly &A0, const Poly &A);

	static void PolyEtaPack(std::vector<byte> &R, size_t ROffset, const Poly &A, uint Eta);

	static void PolyEtaUnpack(Poly &R, const std::vector<byte> &A, size_t AOffset, uint Eta);

	static void PolyFreeze(Poly &A);

	static void PolyInvNttMontgomery(Poly &A);

	static uint PolyMakeHint(Poly &H, const Poly &A, const Poly &B);

	static void PolyNtt(Poly &A);

	static void PolyPointwiseInvMontgomery(Poly &C, const Poly &A, const Poly &B);

	static void PolyPower2Round(Poly &A1, Poly &A0, const Poly &A);

	static void PolyReduce(Poly &A);

	static void PolyShiftL(Poly &A, uint Shift);

	static void PolySub(Poly &C, const Poly &A, const Poly &B);

	static void PolyT0Pack(std::vector<byte> &R, size_t ROffset, const Poly &A);

	static void PolyT0Unpack(Poly &R, const std::vector<byte> &A, size_t AOffset);

	static void PolyT1Pack(std::vector<byte> &R, size_t ROffset, const Poly &A);

	static void PolyT1Unpack(Poly &R, const std::vector<byte> &A, size_t AOffset);

	static void PolyUniform(Poly &A, const std::vector<byte> &Input);

	static void PolyUniformEta(Poly &A, const std::vector<byte> &Seed, byte Nonce, uint Eta);

	static void PolyUniformGamma1M1(Poly &A, const std::vector<byte> &Seed, const std::vector<byte> &Mu, ushort Nonce);

	static void PolyUseHint(Poly &A, const Poly &B, const Poly &H);

	static void PolyW1Pack(std::vector<byte> &R, size_t ROffset, const Poly &A);

	static void PolyZPack(std::vector<byte> &R, size_t ROffset, const Poly &A);

	static void PolyZUnpack(Poly &R, const std::vector<byte> &A, size_t AOffset);

	static uint Power2Round(uint A, uint &A0);

	static uint Reduce32(uint A);

	static uint RejEta(std::array<uint, 256> &A, size_t AOffset, size_t ALength, const std::vector<byte> &Input, size_t InLength, uint Eta);

	static uint RejGamma1M1(std::array<uint, 256> &A, size_t Offset, size_t ALength, const std::vector<byte> &Buffer, size_t BufLength);

	static void Squeeze(std::array<ulong, 25> &State, std::vector<byte> &Output, size_t Blocks);

	static void UnPackPk(std::vector<byte> &Rho, PolyVec &T1, const std::vector<byte> &Pk);

	static bool UnPackSig(PolyVec &Z, PolyVec &H, Poly &C, const std::vector<byte> &Signature, uint Omega);

	static void UnPackSk(std::vector<byte> &Rho, std::vector<byte> &Key, std::vector<byte> &Tr, PolyVec &S1, PolyVec &S2, PolyVec &T0, const std::vector<byte> &Sk, uint Eta, size_t EtaPack);

	static uint UseHint(uint A, uint Hint);

	static void XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate);

public:

	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, DilithiumParameters Params);

	static DlmParams GetParams(DilithiumParameters ParamType);

	static size_t Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, DilithiumParameters Params);

	static bool Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey, DilithiumParameters Params);
};

NAMESPACE_DILITHIUMEND
#endif
