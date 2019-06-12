#ifndef CEX_DLTMK5Q8380417N256_H
#define CEX_DLTMK5Q8380417N256_H

#include "CexConfig.h"
#include "IPrng.h"

NAMESPACE_DILITHIUM

using Prng::IPrng;

/// <summary>
/// The Dilithium K5 (strong security) support class
/// </summary>
class DLTMK5Q8380417N256
{
private:

	static const int32_t DILITHIUM_SEED_SIZE = 32;
	static const int32_t DILITHIUM_CRH_SIZE = 48;
	static const int32_t DILITHIUM_N = 256;
	static const int32_t DILITHIUM_Q = 8380417;
	static const int32_t DILITHIUM_QBITS = 23;
	static const int32_t DILITHIUM_UNITYROOT = 1753;
	static const int32_t DILITHIUM_D = 14;
	static const int32_t DILITHIUM_GAMMA1 = ((DILITHIUM_Q - 1) / 16);
	static const int32_t DILITHIUM_GAMMA2 = (DILITHIUM_GAMMA1 / 2);
	static const int32_t DILITHIUM_ALPHA = (2 * DILITHIUM_GAMMA2);

	static const int32_t DILITHIUM_K = 5;
	static const int32_t DILITHIUM_L = 4;
	static const int32_t DILITHIUM_ETA = 5;
	static const int32_t DILITHIUM_SETABITS = 4;
	static const int32_t DILITHIUM_BETA = 275;
	static const int32_t DILITHIUM_OMEGA = 96;
	static const size_t DILITHIUM_POLETA_SIZE_PACKED = ((DILITHIUM_N * DILITHIUM_SETABITS) / 8);
	static const size_t DILITHIUM_POLT0_SIZE_PACKED = ((DILITHIUM_N * DILITHIUM_D) / 8);
	static const size_t DILITHIUM_POLT1_SIZE_PACKED = ((DILITHIUM_N * (DILITHIUM_QBITS - DILITHIUM_D)) / 8);
	static const size_t DILITHIUM_POLW1_SIZE_PACKED = ((DILITHIUM_N * 4) / 8);
	static const size_t DILITHIUM_POLZ_SIZE_PACKED = ((DILITHIUM_N * (DILITHIUM_QBITS - 3)) / 8);

	static void XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate);

public:

	static const size_t DILITHIUM_PUBLICKEY_SIZE = (DILITHIUM_SEED_SIZE + DILITHIUM_K * DILITHIUM_POLT1_SIZE_PACKED);
	static const size_t DILITHIUM_SECRETKEY_SIZE = (2 * DILITHIUM_SEED_SIZE + (DILITHIUM_L + DILITHIUM_K) * DILITHIUM_POLETA_SIZE_PACKED + DILITHIUM_CRH_SIZE + DILITHIUM_K * DILITHIUM_POLT0_SIZE_PACKED);
	static const size_t DILITHIUM_SIGNATURE_SIZE = (DILITHIUM_L * DILITHIUM_POLZ_SIZE_PACKED + (DILITHIUM_OMEGA + DILITHIUM_K) + (DILITHIUM_N / 8 + 8));

	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);

	static void Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);

	static bool Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey);
};

NAMESPACE_DILITHIUMEND
#endif
