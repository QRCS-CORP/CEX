#ifndef CEX_DLTMK4Q8380417N256_H
#define CEX_DLTMK4Q8380417N256_H

#include "CexConfig.h"
#include "IPrng.h"

NAMESPACE_DILITHIUM

using Prng::IPrng;

/// <summary>
/// The Dilithium K4 (medium security) support class
/// </summary>
class DLTM4880
{
private:

//#define DILITHIUM_MODE 2
//
//#if (DILITHIUM_MODE == 2)
//#   define DILITHIUM_K 4
//#   define DILITHIUM_L 4
//#elif (DILITHIUM_MODE == 3)
//#   define DILITHIUM_K 6
//#   define DILITHIUM_L 5
//#elif (DILITHIUM_MODE == 5)
//#   define DILITHIUM_K 8
//#   define DILITHIUM_L 7
//#endif
//
//#define DILITHIUM_N 256
//#define DILITHIUM_MONT -4186625 /* 2^32 % DILITHIUM_Q */
//#define DILITHIUM_QINV 58728449 /* q^(-1) mod 2^32 */
//
//#define DILITHIUM_SEEDBYTES 32
//#define DILITHIUM_CRHBYTES 48
//#define DILITHIUM_Q 8380417
//#define DILITHIUM_D 13
//#define DILITHIUM_ROOT_OF_UNITY 1753
//
//#if (DILITHIUM_MODE == 2)
//#   define DILITHIUM_ETA 2
//#   define DILITHIUM_TAU 39
//#   define DILITHIUM_BETA 78
//#   define DILITHIUM_GAMMA1 (1 << 17)
//#   define DILITHIUM_GAMMA2 ((DILITHIUM_Q-1) / 88)
//#   define DILITHIUM_OMEGA 80
//#elif (DILITHIUM_MODE == 3)
//#   define DILITHIUM_ETA 4
//#   define DILITHIUM_TAU 49
//#   define DILITHIUM_BETA 196
//#   define DILITHIUM_GAMMA1 (1 << 19)
//#   define DILITHIUM_GAMMA2 ((DILITHIUM_Q-1) / 32)
//#   define DILITHIUM_OMEGA 55
//#elif (DILITHIUM_MODE == 5)
//#   define DILITHIUM_ETA 2
//#   define DILITHIUM_TAU 60
//#   define DILITHIUM_BETA 120
//#   define DILITHIUM_GAMMA1 (1 << 19)
//#   define DILITHIUM_GAMMA2 ((DILITHIUM_Q - 1) / 32)
//#   define DILITHIUM_OMEGA 75
//#endif
//
//#define DILITHIUM_POLYT1_PACKEDBYTES  320
//#define DILITHIUM_POLYT0_PACKEDBYTES  416
//#define DILITHIUM_POLYVECH_PACKEDBYTES (DILITHIUM_OMEGA + DILITHIUM_K)
//
//#if (DILITHIUM_GAMMA1 == (1 << 17))
//#   define DILITHIUM_POLYZ_PACKEDBYTES 576
//#elif (DILITHIUM_GAMMA1 == (1 << 19))
//#   define DILITHIUM_POLYZ_PACKEDBYTES 640
//#endif
//
//#if (DILITHIUM_GAMMA2 == (DILITHIUM_Q-1) / 88)
//#   define DILITHIUM_POLYW1_PACKEDBYTES 192
//#elif (DILITHIUM_GAMMA2 == (DILITHIUM_Q-1) / 32)
//#   define DILITHIUM_POLYW1_PACKEDBYTES 128
//#endif
//
//#if (DILITHIUM_ETA == 2)
//#   define DILITHIUM_POLYETA_PACKEDBYTES 96
//#elif (DILITHIUM_ETA == 4)
//#   define DILITHIUM_POLYETA_PACKEDBYTES 128
//#endif
//
//#define DILITHIUM_PUBLICKEY_SIZE (DILITHIUM_SEEDBYTES + DILITHIUM_K * DILITHIUM_POLYT1_PACKEDBYTES)
//#define DILITHIUM_PRIVATEKEY_SIZE (2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES \
//                               + DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES \
//                               + DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES \
//                               + DILITHIUM_K * DILITHIUM_POLYT0_PACKEDBYTES)
//#define DILITHIUM_SIGNATURE_SIZE (DILITHIUM_SEEDBYTES + DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES + DILITHIUM_POLYVECH_PACKEDBYTES)
//
//#define DILITHIUM_POLY_UNIFORM_NBLOCKS ((768 + QSC_KECCAK_128_RATE - 1) / QSC_KECCAK_128_RATE)
//
//#if (DILITHIUM_ETA == 2)
//#   define DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS ((136 + QSC_KECCAK_128_RATE - 1) / QSC_KECCAK_128_RATE)
//#elif (DILITHIUM_ETA == 4)
//#   define DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS ((227 + QSC_KECCAK_128_RATE - 1) / QSC_KECCAK_128_RATE)
//#endif
//
//#if (DILITHIUM_GAMMA1 == (1 << 17))
//#   define DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS ((576 + QSC_KECCAK_256_RATE - 1) / QSC_KECCAK_256_RATE)
//#elif (DILITHIUM_GAMMA1 == (1 << 19))
//#   define DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS ((640 + QSC_KECCAK_256_RATE - 1) / QSC_KECCAK_256_RATE)
//#endif



	static const size_t DILITHIUM_SEED_SIZE = 32;
	static const size_t DILITHIUM_CRH_SIZE = 48;
	static const uint32_t DILITHIUM_N = 256;
	static const int32_t DILITHIUM_Q = 8380417;
	static const int32_t DILITHIUM_QBITS = 23;
	static const int32_t DILITHIUM_UNITYROOT = 1753;
	static const int32_t DILITHIUM_D = 13;
	static const int32_t DILITHIUM_GAMMA1 = (1 << 17);
	static const int32_t DILITHIUM_GAMMA2 = ((DILITHIUM_Q - 1) / 88);
	static const int32_t DILITHIUM_ALPHA = (2 * DILITHIUM_GAMMA2);
	// 2^32 % Q 
	static const int32_t DILITHIUM_MONT = -4186625;
	// -q^(-1) mod 2^32 
	static const int32_t DILITHIUM_QINV = 58728449;

	static const uint32_t DILITHIUM_K = 4;
	static const uint32_t DILITHIUM_L = 4;
	static const uint32_t DILITHIUM_ETA = 2;
	static const uint32_t DILITHIUM_SETABITS = 4;
	static const uint32_t DILITHIUM_BETA = 78;
	static const uint32_t DILITHIUM_OMEGA = 80;
	static const size_t DILITHIUM_POLETA_SIZE_PACKED = 96;
	static const size_t DILITHIUM_POLT0_SIZE_PACKED = 416;
	static const size_t DILITHIUM_POLT1_SIZE_PACKED = 320;
	static const size_t DILITHIUM_POLW1_SIZE_PACKED = 192;
	static const size_t DILITHIUM_POLZ_SIZE_PACKED = 576;
	static const uint32_t DILITHIUM_TAU = 39;

public:

	static const size_t DILITHIUM_PUBLICKEY_SIZE = 1312;
	static const size_t DILITHIUM_SECRETKEY_SIZE = 2544;
	static const size_t DILITHIUM_SIGNATURE_SIZE = 2420;
	static void Generate(std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);
	static void Sign(std::vector<uint8_t> &Signature, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);
	static bool Verify(std::vector<uint8_t> &Message, const std::vector<uint8_t> &Signature, const std::vector<uint8_t> &PublicKey);
};

NAMESPACE_DILITHIUMEND
#endif
