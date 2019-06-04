#include "MLWEQ3329N256.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "Keccak.h"

NAMESPACE_MODULELWE

using Utility::IntegerTools;
using Digest::Keccak;
using Utility::MemoryTools;

//~~~Constants~~~//

const std::vector<int16_t> MLWEQ3329N256::Zetas =
{
	0x08ED, 0x0A0B, 0x0B9A, 0x0714, 0x05D5, 0x058E, 0x011F, 0x00CA, 0x0C56, 0x026E, 0x0629, 0x00B6, 0x03C2, 0x084F, 0x073F, 0x05BC,
	0x023D, 0x07D4, 0x0108, 0x017F, 0x09C4, 0x05B2, 0x06BF, 0x0C7F, 0x0A58, 0x03F9, 0x02DC, 0x0260, 0x06FB, 0x019B, 0x0C34, 0x06DE,
	0x04C7, 0x028C, 0x0AD9, 0x03F7, 0x07F4, 0x05D3, 0x0BE7, 0x06F9, 0x0204, 0x0CF9, 0x0BC1, 0x0A67, 0x06AF, 0x0877, 0x007E, 0x05BD,
	0x09AC, 0x0CA7, 0x0BF2, 0x033E, 0x006B, 0x0774, 0x0C0A, 0x094A, 0x0B73, 0x03C1, 0x071D, 0x0A2C, 0x01C0, 0x08D8, 0x02A5, 0x0806,
	0x08B2, 0x01AE, 0x022B, 0x034B, 0x081E, 0x0367, 0x060E, 0x0069, 0x01A6, 0x024B, 0x00B1, 0x0C16, 0x0BDE, 0x0B35, 0x0626, 0x0675,
	0x0C0B, 0x030A, 0x0487, 0x0C6E, 0x09F8, 0x05CB, 0x0AA7, 0x045F, 0x06CB, 0x0284, 0x0999, 0x015D, 0x01A2, 0x0149, 0x0C65, 0x0CB6,
	0x0331, 0x0449, 0x025B, 0x0262, 0x052A, 0x07FC, 0x0748, 0x0180, 0x0842, 0x0C79, 0x04C2, 0x07CA, 0x0997, 0x00DC, 0x085E, 0x0686,
	0x0860, 0x0707, 0x0803, 0x031A, 0x071B, 0x09AB, 0x099B, 0x01DE, 0x0C95, 0x0BCD, 0x03E4, 0x03DF, 0x03BE, 0x074D, 0x05F2, 0x065C
};

const std::vector<int16_t> MLWEQ3329N256::ZetasInv =
{
	0x06A5, 0x070F, 0x05B4, 0x0943, 0x0922, 0x091D, 0x0134, 0x006C, 0x0B23, 0x0366, 0x0356, 0x05E6, 0x09E7, 0x04FE, 0x05FA, 0x04A1,
	0x067B, 0x04A3, 0x0C25, 0x036A, 0x0537, 0x083F, 0x0088, 0x04BF, 0x0B81, 0x05B9, 0x0505, 0x07D7, 0x0A9F, 0x0AA6, 0x08B8, 0x09D0,
	0x004B, 0x009C, 0x0BB8, 0x0B5F, 0x0BA4, 0x0368, 0x0A7D, 0x0636, 0x08A2, 0x025A, 0x0736, 0x0309, 0x0093, 0x087A, 0x09F7, 0x00F6,
	0x068C, 0x06DB, 0x01CC, 0x0123, 0x00EB, 0x0C50, 0x0AB6, 0x0B5B, 0x0C98, 0x06F3, 0x099A, 0x04E3, 0x09B6, 0x0AD6, 0x0B53, 0x044F,
	0x04FB, 0x0A5C, 0x0429, 0x0B41, 0x02D5, 0x05E4, 0x0940, 0x018E, 0x03B7, 0x00F7, 0x058D, 0x0C96, 0x09C3, 0x010F, 0x005A, 0x0355,
	0x0744, 0x0C83, 0x048A, 0x0652, 0x029A, 0x0140, 0x0008, 0x0AFD, 0x0608, 0x011A, 0x072E, 0x050D, 0x090A, 0x0228, 0x0A75, 0x083A,
	0x0623, 0x00CD, 0x0B66, 0x0606, 0x0AA1, 0x0A25, 0x0908, 0x02A9, 0x0082, 0x0642, 0x074F, 0x033D, 0x0B82, 0x0BF9, 0x052D, 0x0AC4,
	0x0745, 0x05C2, 0x04B2, 0x093F, 0x0C4B, 0x06D8, 0x0A93, 0x00AB, 0x0C37, 0x0BE2, 0x0773, 0x072C, 0x05ED, 0x0167, 0x02F6, 0x05A1
};

//~~~Public Functions~~~//

bool MLWEQ3329N256::Decapsulate(std::vector<byte> &Secret, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey)
{
	const size_t KLEN = (CipherText.size() == CIPHERTEXTK2_SIZE) ? 2 : (CipherText.size() == CIPHERTEXTK3_SIZE) ? 3 : 4;
	const size_t PRILEN = MLWE_POLY_SIZE * KLEN;
	std::vector<byte> buf(2 * MLWE_SEED_SIZE);
	std::vector<byte> cmp(CipherText.size());
	std::vector<byte> kr(2 * MLWE_SEED_SIZE);
	std::vector<byte> pk(PrivateKey.size() - PRILEN);
	std::vector<byte> seed(MLWE_SEED_SIZE);
	int32_t fail;

	// decrypt the coin
	CpaDecrypt(buf, CipherText, PrivateKey, KLEN);

	// multitarget countermeasure for coins + contributory KEM
	MemoryTools::Copy(PrivateKey, PrivateKey.size() - (2 * MLWE_SEED_SIZE), buf, MLWE_SEED_SIZE, MLWE_SEED_SIZE);
	// coins are in kr+MLWE_SEED_SIZE
	Compute(buf, 0, 2 * MLWE_SEED_SIZE, kr, 0, Keccak::KECCAK512_DIGEST_SIZE, Keccak::KECCAK512_RATE_SIZE);
	// encrypt the cipher-text
	MemoryTools::Copy(kr, MLWE_SEED_SIZE, seed, 0, seed.size());
	MemoryTools::Copy(PrivateKey, PRILEN, pk, 0, pk.size());
	// generate a new ciphertext for comparison
	CpaEncrypt(cmp, buf, pk, seed, KLEN);

	// compare the input ciphertext with the newly generated vector
	fail = IntegerTools::Verify(CipherText, cmp, CipherText.size());

	// overwrite coins in kr with H(c)
	Compute(CipherText, 0, CipherText.size(), kr, MLWE_SEED_SIZE, MLWE_SEED_SIZE, Keccak::KECCAK256_RATE_SIZE);
	// overwrite pre-k with z on re-encryption failure
	IntegerTools::CMov(PrivateKey, PrivateKey.size() - MLWE_SEED_SIZE, kr, 0, MLWE_SEED_SIZE, static_cast<byte>(fail));
	// hash concatenation of pre-k and H(c) to k
	XOF(kr, 0, 2 * MLWE_SEED_SIZE, Secret, 0, Secret.size(), Keccak::KECCAK256_RATE_SIZE);

	return (fail == 0);
}

void MLWEQ3329N256::Encapsulate(std::vector<byte> & Secret, std::vector<byte> & CipherText, const std::vector<byte> & PublicKey, std::unique_ptr<Prng::IPrng> & Rng)
{
	const size_t KLEN = (PublicKey.size() - MLWE_SEED_SIZE) / MLWE_POLY_SIZE;
	// will contain key, coins
	std::vector<byte> kr(2 * MLWE_SEED_SIZE);
	std::vector<byte> ktmp(MLWE_SEED_SIZE);
	std::vector<byte> buf(2 * MLWE_SEED_SIZE);

	// generate the seed buffer
	Rng->Generate(buf, 0, MLWE_SEED_SIZE);
	// don't release system RNG output
	Compute(buf, 0, MLWE_SEED_SIZE, buf, 0, MLWE_SEED_SIZE, Keccak::KECCAK256_RATE_SIZE);
	// multitarget countermeasure for coins + contributory KEM
	Compute(PublicKey, 0, PublicKey.size(), buf, MLWE_SEED_SIZE, MLWE_SEED_SIZE, Keccak::KECCAK256_RATE_SIZE);
	Compute(buf, 0, 2 * MLWE_SEED_SIZE, kr, 0, 2 * MLWE_SEED_SIZE, Keccak::KECCAK512_RATE_SIZE);

	// coins are in kr+MLWE_SEED_SIZE
	MemoryTools::Copy(kr, MLWE_SEED_SIZE, ktmp, 0, MLWE_SEED_SIZE);
	// encrypt the coin
	CpaEncrypt(CipherText, buf, PublicKey, ktmp, KLEN);
	// overwrite coins in kr with H(c)
	Compute(CipherText, 0, CipherText.size(), kr, MLWE_SEED_SIZE, MLWE_SEED_SIZE, Keccak::KECCAK256_RATE_SIZE);
	// hash concatenation of pre-k and H(c) to k
	XOF(kr, 0, 2 * MLWE_SEED_SIZE, Secret, 0, Secret.size(), Keccak::KECCAK256_RATE_SIZE);
}

void MLWEQ3329N256::Generate(std::vector<byte> & PublicKey, std::vector<byte> & PrivateKey, std::unique_ptr<Prng::IPrng> & Rng)
{
	const size_t KLEN = (PublicKey.size() - MLWE_SEED_SIZE) / MLWE_POLY_SIZE;
	const size_t PRILEN = KLEN * MLWE_POLY_SIZE;
	std::vector<byte> seed(2 * MLWE_SEED_SIZE);

	// generate the seed, and expand it with keccak-512
	Rng->Generate(seed, 0, MLWE_SEED_SIZE);
	Compute(seed, 0, MLWE_SEED_SIZE, seed, 0, Keccak::KECCAK512_DIGEST_SIZE, Keccak::KECCAK512_RATE_SIZE);
	// generate the CPA base key-pair
	CpaGenerate(PublicKey, PrivateKey, seed, KLEN);
	// copy the public key to the private key
	MemoryTools::Copy(PublicKey, 0, PrivateKey, PRILEN, PublicKey.size());
	// calculate the public key hash H(pk) and add it to the private key
	Compute(PublicKey, 0, PublicKey.size(), PrivateKey, PrivateKey.size() - (2 * MLWE_SEED_SIZE), Keccak::KECCAK256_DIGEST_SIZE, Keccak::KECCAK256_RATE_SIZE);
	// value z for pseudo-random output on reject
	Rng->Generate(PrivateKey, PrivateKey.size() - MLWE_SEED_SIZE, MLWE_SEED_SIZE);
}

// indcpa.c //

void MLWEQ3329N256::PackPk(std::vector<byte> & R, std::vector<std::array<ushort, MLWE_N>> & Pk, const std::vector<byte> & Seed)
{
	const size_t PKOFT = Pk.size() * MLWE_POLY_SIZE;

	PolyVecToBytes(R, Pk);
	MemoryTools::Copy(Seed, 0, R, PKOFT, MLWE_SEED_SIZE);
}

void MLWEQ3329N256::UnpackPk(std::vector<std::array<ushort, MLWE_N>> & Pk, std::vector<byte> & Seed, const std::vector<byte> & PackedPk, uint Dimension)
{
	const size_t PLYVEC = Dimension * MLWE_POLY_SIZE;

	PolyVecFromBytes(Pk, PackedPk);
	MemoryTools::Copy(PackedPk, PLYVEC, Seed, 0, MLWE_SEED_SIZE);
}

void MLWEQ3329N256::PackSk(std::vector<byte> & R, std::vector<std::array<ushort, MLWE_N>> & Sk)
{
	PolyVecToBytes(R, Sk);
}

void MLWEQ3329N256::UnpackSk(std::vector<std::array<ushort, MLWE_N>> & Sk, const std::vector<byte> & PackedSk)
{
	PolyVecFromBytes(Sk, PackedSk);
}

void MLWEQ3329N256::PackCiphertext(std::vector<byte> & R, std::vector<std::array<ushort, MLWE_N>> & B, std::array<ushort, MLWE_N> & V)
{
	PolyVecCompress(R, B);
	PolyCompress(R, V, B.size());
}

void MLWEQ3329N256::UnpackCiphertext(std::vector<std::array<ushort, MLWE_N>> & B, std::array<ushort, MLWE_N> & V, const std::vector<byte> & C)
{
	PolyVecDecompress(B, C);
	PolyDecompress(V, C, B.size());
}

uint MLWEQ3329N256::RejUniform(std::array<ushort, MLWE_N> & R, uint ROffset, uint RLength, const std::vector<byte> & Buffer, size_t BufLength)
{
	uint ctr;
	uint pos;
	ushort val;

	ctr = ROffset;
	pos = 0;

	while (ctr < RLength && pos + 2 <= BufLength)
	{
		val = Buffer[pos] | (static_cast<ushort>(Buffer[pos + 1]) << 8);
		pos += 2;

		if (val < 19 * MLWE_Q)
		{
			// Barrett reduction
			val -= (val >> 12) * MLWE_Q;
			R[ctr] = val;
			++ctr;
		}
	}

	return ctr;
}

void MLWEQ3329N256::GenMatrix(std::vector<std::vector<std::array<ushort, MLWE_N>>> & A, const std::vector<byte> & Seed, bool Transposed)
{
	// 530 is expected number of required bytes
	const size_t KLEN = A.size();
	const uint maxnblocks = (530 + Keccak::KECCAK128_RATE_SIZE) / Keccak::KECCAK128_RATE_SIZE;
	std::vector<byte> buf(Keccak::KECCAK128_RATE_SIZE * ((530 + Keccak::KECCAK128_RATE_SIZE) / Keccak::KECCAK128_RATE_SIZE) + 1);
	std::array<ulong, Keccak::KECCAK_STATE_SIZE> state;
	std::vector<byte> extseed(MLWE_SEED_SIZE + 2);
	size_t i;
	size_t j;
	size_t k;
	uint ctr;

	for (i = 0; i < KLEN; ++i)
	{
		for (j = 0; j < KLEN; ++j)
		{
			MemoryTools::Copy(Seed, 0, extseed, 0, MLWE_SEED_SIZE);
			k = MLWE_SEED_SIZE;

			if (Transposed)
			{
				extseed[k] = static_cast<byte>(i);
				++k;
				extseed[k] = static_cast<byte>(j);
			}
			else
			{
				extseed[k] = static_cast<byte>(j);
				++k;
				extseed[k] = static_cast<byte>(i);
			}

			MemoryTools::SetValue(state, 0, state.size() * sizeof(ulong), 0x00);
			Keccak::AbsorbR24(extseed, 0, MLWE_SEED_SIZE + 2, Keccak::KECCAK128_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, state);
			Keccak::SqueezeR24(state, buf, 0, maxnblocks, Keccak::KECCAK128_RATE_SIZE);

			ctr = RejUniform(A[i][j], 0, MLWE_N, buf, maxnblocks * Keccak::KECCAK128_RATE_SIZE);

			while (ctr < MLWE_N)
			{
				Keccak::SqueezeR24(state, buf, 0, 1, Keccak::KECCAK128_RATE_SIZE);
				ctr += RejUniform(A[i][j], ctr, MLWE_N - ctr, buf, Keccak::KECCAK128_RATE_SIZE);
			}
		}
	}
}

void MLWEQ3329N256::CpaGenerate(std::vector<byte> & PublicKey, std::vector<byte> & PrivateKey, std::vector<byte> & Seed, uint K)
{
	std::vector<std::vector<std::array<ushort, MLWE_N>>> a(K, std::vector<std::array<ushort, MLWE_N>>(K));
	std::vector<std::array<ushort, MLWE_N>> e(K);
	std::vector<std::array<ushort, MLWE_N>> pkpv(K);
	std::vector<std::array<ushort, MLWE_N>> skpv(K);
	std::vector<byte> nseed(MLWE_SEED_SIZE);
	std::vector<byte> pseed(MLWE_SEED_SIZE);
	size_t i;
	byte nonce;

	MemoryTools::Copy(Seed, 0, pseed, 0, MLWE_SEED_SIZE);
	MemoryTools::Copy(Seed, MLWE_SEED_SIZE, nseed, 0, MLWE_SEED_SIZE);

	nonce = 0;
	GenMatrix(a, pseed, 0);

	for (i = 0; i < K; ++i)
	{
		PolyGetNoise(skpv[i], nseed, nonce);
		++nonce;
	}

	for (i = 0; i < K; ++i)
	{
		PolyGetNoise(e[i], nseed, nonce);
		++nonce;
	}

	PolyVecNtt(skpv);
	PolyVecNtt(e);

	// matrix-vector multiplication
	for (i = 0; i < K; ++i)
	{
		PolyVecPointwiseAcc(pkpv[i], a[i], skpv);
		PolyFromMont(pkpv[i]);
	}

	PolyVecAdd(pkpv, pkpv, e);
	PolyVecReduce(pkpv);

	PackSk(PrivateKey, skpv);
	PackPk(PublicKey, pkpv, pseed);
}

void MLWEQ3329N256::CpaEncrypt(std::vector<byte> & CipherText, const std::vector<byte> & Message, const std::vector<byte> & Pk, const std::vector<byte> & Coins, uint K)
{
	std::vector<byte> seed(MLWE_SEED_SIZE);
	std::vector<std::vector<std::array<ushort, MLWE_N>>> at(K, std::vector<std::array<ushort, MLWE_N>>(K));
	std::vector<std::array<ushort, MLWE_N>> bp(K);
	std::vector<std::array<ushort, MLWE_N>> sp(K);
	std::vector<std::array<ushort, MLWE_N>> pkpv(K);
	std::vector<std::array<ushort, MLWE_N>> ep(K);
	std::array<ushort, MLWE_N> k;
	std::array<ushort, MLWE_N> epp;
	std::array<ushort, MLWE_N> v;
	size_t i;
	uint8_t nonce;

	nonce = 0;
	UnpackPk(pkpv, seed, Pk, K);
	PolyFromMsg(k, Message);
	GenMatrix(at, seed, 1);

	for (i = 0; i < K; ++i)
	{
		PolyGetNoise(sp[i], Coins, nonce);
		++nonce;
	}

	for (i = 0; i < K; ++i)
	{
		PolyGetNoise(ep[i], Coins, nonce);
		++nonce;
	}

	PolyGetNoise(epp, Coins, nonce);
	++nonce;
	PolyVecNtt(sp);

	// matrix-vector multiplication
	for (i = 0; i < K; ++i)
	{
		PolyVecPointwiseAcc(bp[i], at[i], sp);
	}

	PolyVecPointwiseAcc(v, pkpv, sp);
	PolyVecInvNtt(bp);
	PolyInvNtt(v);

	PolyVecAdd(bp, bp, ep);
	PolyAdd(v, v, epp);
	PolyAdd(v, v, k);
	PolyVecReduce(bp);
	PolyReduce(v);

	PackCiphertext(CipherText, bp, v);
}

void MLWEQ3329N256::CpaDecrypt(std::vector<byte> & Message, const std::vector<byte> & CipherText, const std::vector<byte> & Sk, uint K)
{
	std::vector<std::array<ushort, MLWE_N>> bp(K);
	std::vector<std::array<ushort, MLWE_N>> skpv(K);
	std::array<ushort, MLWE_N> v;
	std::array<ushort, MLWE_N> mp;

	UnpackCiphertext(bp, v, CipherText);
	UnpackSk(skpv, Sk);

	PolyVecNtt(bp);
	PolyVecPointwiseAcc(mp, skpv, bp);
	PolyInvNtt(mp);

	PolySub(mp, v, mp);
	PolyReduce(mp);

	PolyToMsg(Message, mp);
}

// ntt.c //

ushort MLWEQ3329N256::FqMul(int16_t A, int16_t B)
{
	return MontgomeryReduce(static_cast<int32_t>(A) * B);
}

void MLWEQ3329N256::Ntt(std::array<ushort, MLWE_N> & R)
{
	uint j;
	uint k;
	uint len;
	uint start;
	ushort t;
	int16_t zeta;

	k = 1;

	for (len = 128; len >= 2; len >>= 1)
	{
		for (start = 0; start < 256; start = j + len)
		{
			zeta = Zetas[k];
			++k;

			for (j = start; j < start + len; ++j)
			{
				t = FqMul(zeta, static_cast<int16_t>(R[j + len]));
				R[j + len] = R[j] - t;
				R[j] = R[j] + t;
			}
		}
	}
}

void MLWEQ3329N256::InvNtt(std::array<ushort, MLWE_N> & R)
{
	uint j;
	uint k;
	uint len;
	uint start;
	ushort t;
	int16_t zeta;

	k = 0;

	for (len = 2; len <= 128; len <<= 1)
	{
		for (start = 0; start < 256; start = j + len)
		{
			zeta = ZetasInv[k];
			++k;

			for (j = start; j < start + len; ++j)
			{
				t = R[j];
				R[j] = BarrettReduce(static_cast<int16_t>(t + R[j + len]));
				R[j + len] = t - R[j + len];
				R[j + len] = FqMul(zeta, static_cast<int16_t>(R[j + len]));
			}
		}
	}

	for (j = 0; j < 256; ++j)
	{
		R[j] = FqMul(static_cast<int16_t>(R[j]), ZetasInv[127]);
	}
}

void MLWEQ3329N256::BaseMul(std::array<ushort, MLWE_N> & R, const std::array<ushort, MLWE_N> & A, const std::array<ushort, MLWE_N> & B, size_t Offset, int16_t Zeta)
{
	R[Offset] = FqMul(static_cast<int16_t>(A[Offset + 1]), static_cast<int16_t>(B[Offset + 1]));
	R[Offset] = FqMul(static_cast<int16_t>(R[Offset]), Zeta);
	R[Offset] += FqMul(static_cast<int16_t>(A[Offset]), static_cast<int16_t>(B[Offset]));
	R[Offset + 1] = FqMul(static_cast<int16_t>(A[Offset]), static_cast<int16_t>(B[Offset + 1]));
	R[Offset + 1] += FqMul(static_cast<int16_t>(A[Offset + 1]), static_cast<int16_t>(B[Offset]));
}

// poly.c //

void MLWEQ3329N256::Cbd(std::array<ushort, MLWE_N> & R, const std::vector<byte> & Buffer)
{
	size_t i;
	size_t j;
	uint d;
	uint t;
	int16_t a;
	int16_t b;

	for (i = 0; i < MLWE_N / 8; ++i)
	{
		t = IntegerTools::LeBytesTo32(Buffer, 4 * i);
		d = t & 0x55555555UL;
		d += (t >> 1) & 0x55555555UL;

		for (j = 0; j < 8; j++)
		{
			a = (d >> (4 * j)) & 0x03;
			b = (d >> ((4 * j) + 2)) & 0x03;
			R[(8 * i) + j] = static_cast<ushort>(a - b);
		}
	}
}

void MLWEQ3329N256::PolyCompress(std::vector<byte> & R, std::array<ushort, MLWE_N> & A, uint K)
{
	std::array<byte, 8> t;
	size_t i;
	size_t j;
	size_t kctr;

	kctr = K != 4 ? K * 320 : K * 352;
	PolyCSubQ(A);

	if (K == 2)
	{
		for (i = 0; i < MLWE_N; i += 8)
		{
			for (j = 0; j < 8; ++j)
			{
				t[j] = (((static_cast<uint>(A[i + j]) << 3) + MLWE_Q / 2) / MLWE_Q) & 7;
			}

			R[kctr] = t[0] | (t[1] << 3) | (t[2] << 6);
			R[kctr + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
			R[kctr + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
			kctr += 3;
		}
	}
	else if (K == 3)
	{
		for (i = 0; i < MLWE_N; i += 8)
		{
			for (j = 0; j < 8; ++j)
			{
				t[j] = (((static_cast<uint>(A[i + j]) << 4) + MLWE_Q / 2) / MLWE_Q) & 15;
			}

			R[kctr] = static_cast<byte>(t[0] | (t[1] << 4));
			R[kctr + 1] = static_cast<byte>(t[2] | (t[3] << 4));
			R[kctr + 2] = static_cast<byte>(t[4] | (t[5] << 4));
			R[kctr + 3] = static_cast<byte>(t[6] | (t[7] << 4));
			kctr += 4;
		}
	}
	else
	{
		for (i = 0; i < MLWE_N; i += 8)
		{
			for (j = 0; j < 8; ++j)
			{
				t[j] = (((static_cast<uint>(A[i + j]) << 5) + MLWE_Q / 2) / MLWE_Q) & 31;
			}

			R[kctr] = static_cast<byte>(t[0] | (t[1] << 5));
			R[kctr + 1] = static_cast<byte>((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
			R[kctr + 2] = static_cast<byte>((t[3] >> 1) | (t[4] << 4));
			R[kctr + 3] = static_cast<byte>((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
			R[kctr + 4] = static_cast<byte>((t[6] >> 2) | (t[7] << 3));
			kctr += 5;
		}
	}
}

void MLWEQ3329N256::PolyDecompress(std::array<ushort, MLWE_N> & R, const std::vector<byte> & A, uint K)
{
	size_t i;
	size_t actr;

	actr = (K != 4) ? K * 320 : K * 352;

	if (K == 2)
	{
		for (i = 0; i < MLWE_N; i += 8)
		{
			R[i] = (((A[actr] & 7) * MLWE_Q) + 4) >> 3;
			R[i + 1] = ((((A[actr] >> 3) & 7) * MLWE_Q) + 4) >> 3;
			R[i + 2] = ((((A[actr] >> 6) | ((A[actr + 1] << 2) & 4)) * MLWE_Q) + 4) >> 3;
			R[i + 3] = ((((A[actr + 1] >> 1) & 7) * MLWE_Q) + 4) >> 3;
			R[i + 4] = ((((A[actr + 1] >> 4) & 7) * MLWE_Q) + 4) >> 3;
			R[i + 5] = ((((A[actr + 1] >> 7) | ((A[actr + 2] << 1) & 6)) * MLWE_Q) + 4) >> 3;
			R[i + 6] = ((((A[actr + 2] >> 2) & 7) * MLWE_Q) + 4) >> 3;
			R[i + 7] = ((((A[actr + 2] >> 5)) * MLWE_Q) + 4) >> 3;
			actr += 3;
		}
	}
	else if (K == 3)
	{
		for (i = 0; i < MLWE_N; i += 8)
		{
			R[i] = (((A[actr] & 15) * MLWE_Q) + 8) >> 4;
			R[i + 1] = (((A[actr] >> 4) * MLWE_Q) + 8) >> 4;
			R[i + 2] = (((A[actr + 1] & 15) * MLWE_Q) + 8) >> 4;
			R[i + 3] = (((A[actr + 1] >> 4) * MLWE_Q) + 8) >> 4;
			R[i + 4] = (((A[actr + 2] & 15) * MLWE_Q) + 8) >> 4;
			R[i + 5] = (((A[actr + 2] >> 4) * MLWE_Q) + 8) >> 4;
			R[i + 6] = (((A[actr + 3] & 15) * MLWE_Q) + 8) >> 4;
			R[i + 7] = (((A[actr + 3] >> 4) * MLWE_Q) + 8) >> 4;
			actr += 4;
		}
	}
	else
	{
		for (i = 0; i < MLWE_N; i += 8)
		{
			R[i] = (((A[actr] & 31) * MLWE_Q) + 16) >> 5;
			R[i + 1] = ((((A[actr] >> 5) | ((A[actr + 1] & 3) << 3)) * MLWE_Q) + 16) >> 5;
			R[i + 2] = ((((A[actr + 1] >> 2) & 31) * MLWE_Q) + 16) >> 5;
			R[i + 3] = ((((A[actr + 1] >> 7) | ((A[actr + 2] & 15) << 1)) * MLWE_Q) + 16) >> 5;
			R[i + 4] = ((((A[actr + 2] >> 4) | ((A[actr + 3] & 1) << 4)) * MLWE_Q) + 16) >> 5;
			R[i + 5] = ((((A[actr + 3] >> 1) & 31) * MLWE_Q) + 16) >> 5;
			R[i + 6] = ((((A[actr + 3] >> 6) | ((A[actr + 4] & 7) << 2)) * MLWE_Q) + 16) >> 5;
			R[i + 7] = (((A[actr + 4] >> 3) * MLWE_Q) + 16) >> 5;
			actr += 5;
		}
	}
}

void MLWEQ3329N256::PolyToBytes(std::vector<byte> & R, size_t ROffset, std::array<ushort, MLWE_N> & A)
{
	size_t i;
	ushort t0;
	ushort t1;

	PolyCSubQ(A);

	for (i = 0; i < MLWE_N / 2; ++i)
	{
		t0 = A[2 * i];
		t1 = A[(2 * i) + 1];
		R[ROffset + (3 * i)] = t0 & 0xFF;
		R[ROffset + (3 * i) + 1] = (t0 >> 8) | ((t1 & 0x0F) << 4);
		R[ROffset + (3 * i) + 2] = static_cast<byte>(t1 >> 4);
	}
}

void MLWEQ3329N256::PolyFromBytes(std::array<ushort, MLWE_N> & R, const std::vector<byte> & A, size_t AOffset)
{
	size_t i;

	for (i = 0; i < MLWE_N / 2; ++i)
	{
		R[2 * i] = A[AOffset + (3 * i)] | (static_cast<ushort>(A[AOffset + (3 * i) + 1]) & 0x0F) << 8;
		R[(2 * i) + 1] = A[AOffset + (3 * i) + 1] >> 4 | (static_cast<ushort>(A[AOffset + (3 * i) + 2]) & 0xFF) << 4;
	}
}

void MLWEQ3329N256::PolyGetNoise(std::array<ushort, MLWE_N> & R, const std::vector<byte> & Seed, byte Nonce)
{
	std::vector<byte> buf(MLWE_ETA * MLWE_N / 4);
	std::vector<byte> extkey(MLWE_SEED_SIZE + 1);

	MemoryTools::Copy(Seed, 0, extkey, 0, MLWE_SEED_SIZE);
	extkey[MLWE_SEED_SIZE] = Nonce;

	XOF(extkey, 0, MLWE_SEED_SIZE + 1, buf, 0, (MLWE_ETA * MLWE_N) / 4, Keccak::KECCAK256_RATE_SIZE);

	Cbd(R, buf);
}

void MLWEQ3329N256::PolyNtt(std::array<ushort, MLWE_N> & R)
{
	Ntt(R);
	PolyReduce(R);
}

void MLWEQ3329N256::PolyInvNtt(std::array<ushort, MLWE_N> & R)
{
	InvNtt(R);
}

void MLWEQ3329N256::PolyBaseMul(std::array<ushort, MLWE_N> & R, const std::array<ushort, MLWE_N> & A, const std::array<ushort, MLWE_N> & B)
{
	size_t i;

	for (i = 0; i < MLWE_N / 4; ++i)
	{
		BaseMul(R, A, B, 4 * i, Zetas[64 + i]);
		BaseMul(R, A, B, 4 * i + 2, -Zetas[64 + i]);
	}
}

void MLWEQ3329N256::PolyFromMont(std::array<ushort, MLWE_N> & R)
{
	const int16_t F = (1ULL << 32) % MLWE_Q;
	size_t i;

	for (i = 0; i < MLWE_N; ++i)
	{
		R[i] = MontgomeryReduce(static_cast<int32_t>(R[i]) * F);
	}
}

void MLWEQ3329N256::PolyReduce(std::array<ushort, MLWE_N> & R)
{
	size_t i;

	for (i = 0; i < MLWE_N; ++i)
	{
		R[i] = BarrettReduce(static_cast<int16_t>(R[i]));
	}
}

void MLWEQ3329N256::PolyCSubQ(std::array<ushort, MLWE_N> & R)
{
	size_t i;

	for (i = 0; i < MLWE_N; ++i)
	{
		R[i] = CSubQ(static_cast<int16_t>(R[i]));
	}
}

void MLWEQ3329N256::PolyAdd(std::array<ushort, MLWE_N> & R, const std::array<ushort, MLWE_N> & A, const std::array<ushort, MLWE_N> & B)
{
	size_t i;

	for (i = 0; i < MLWE_N; ++i)
	{
		R[i] = A[i] + B[i];
	}
}

void MLWEQ3329N256::PolySub(std::array<ushort, MLWE_N> & R, const std::array<ushort, MLWE_N> & A, const std::array<ushort, MLWE_N> & B)
{
	size_t i;

	for (i = 0; i < MLWE_N; ++i)
	{
		R[i] = A[i] - B[i];
	}
}

void MLWEQ3329N256::PolyFromMsg(std::array<ushort, MLWE_N> & R, const std::vector<byte> & Msg)
{
	size_t i;
	size_t j;
	ushort mask;

	for (i = 0; i < MLWE_SEED_SIZE; ++i)
	{
		for (j = 0; j < 8; ++j)
		{
			mask = ~((Msg[i] >> j) & 1) + 1;
			R[(8 * i) + j] = mask & ((MLWE_Q + 1) / 2);
		}
	}
}

void MLWEQ3329N256::PolyToMsg(std::vector<byte> & Msg, std::array<ushort, MLWE_N> & A)
{
	size_t i;
	size_t j;
	ushort t;

	PolyCSubQ(A);

	for (i = 0; i < MLWE_SEED_SIZE; ++i)
	{
		Msg[i] = 0;

		for (j = 0; j < 8; ++j)
		{
			t = (((A[(8 * i) + j] << 1) + MLWE_Q / 2) / MLWE_Q) & 1;
			Msg[i] |= static_cast<byte>(t << j);
		}
	}
}

// polyvec.c //

void MLWEQ3329N256::PolyVecCompress(std::vector<byte> & R, std::vector<std::array<ushort, MLWE_N>> & A)
{
	size_t i;
	size_t j;
	size_t k;
	size_t rctr;

	PolyVecCSubQ(A);
	rctr = 0;

	if (A.size() == 4)
	{
		std::array<ushort, 8> t;

		for (i = 0; i < A.size(); ++i)
		{
			for (j = 0; j < MLWE_N / 8; ++j)
			{
				for (k = 0; k < 8; ++k)
				{
					t[k] = (((static_cast<uint>(A[i][(8 * j) + k]) << 11) + MLWE_Q / 2) / MLWE_Q) & 0x7FF;
				}

				R[rctr + (11 * j)] = t[0] & 0xFF;
				R[rctr + (11 * j) + 1] = (t[0] >> 8) | ((t[1] & 0x1F) << 3);
				R[rctr + (11 * j) + 2] = (t[1] >> 5) | ((t[2] & 0x03) << 6);
				R[rctr + (11 * j) + 3] = (t[2] >> 2) & 0xFF;
				R[rctr + (11 * j) + 4] = (t[2] >> 10) | ((t[3] & 0x7F) << 1);
				R[rctr + (11 * j) + 5] = (t[3] >> 7) | ((t[4] & 0x0F) << 4);
				R[rctr + (11 * j) + 6] = (t[4] >> 4) | ((t[5] & 0x01) << 7);
				R[rctr + (11 * j) + 7] = (t[5] >> 1) & 0xff;
				R[rctr + (11 * j) + 8] = (t[5] >> 9) | ((t[6] & 0x3F) << 2);
				R[rctr + (11 * j) + 9] = (t[6] >> 6) | ((t[7] & 0x07) << 5);
				R[rctr + (11 * j) + 10] = (t[7] >> 3);
			}

			rctr += 352;
		}
	}
	else
	{
		std::array<ushort, 4> t;

		for (i = 0; i < A.size(); ++i)
		{
			for (j = 0; j < MLWE_N / 4; ++j)
			{
				for (k = 0; k < 4; ++k)
				{
					t[k] = (((static_cast<uint>(A[i][(4 * j) + k]) << 10) + MLWE_Q / 2) / MLWE_Q) & 0x3FF;
				}

				R[rctr + (5 * j)] = static_cast<byte>(t[0] & 0xFF);
				R[rctr + (5 * j) + 1] = static_cast<byte>((t[0] >> 8) | ((t[1] & 0x3F) << 2));
				R[rctr + (5 * j) + 2] = static_cast<byte>((t[1] >> 6) | ((t[2] & 0x0F) << 4));
				R[rctr + (5 * j) + 3] = static_cast<byte>((t[2] >> 4) | ((t[3] & 0x03) << 6));
				R[rctr + (5 * j) + 4] = static_cast<byte>((t[3] >> 2));
			}

			rctr += 320;
		}
	}
}

void MLWEQ3329N256::PolyVecDecompress(std::vector<std::array<ushort, MLWE_N>> & R, const std::vector<byte> & A)
{
	const size_t PLYBSE = (R.size() == 4) ? 352 : 320;
	size_t i;
	size_t j;
	size_t actr;

	actr = 0;

	if (R.size() == 4)
	{
		for (i = 0; i < R.size(); ++i)
		{
			for (j = 0; j < MLWE_N / 8; ++j)
			{
				R[i][(8 * j)] = (((A[actr + (11 * j)] | ((static_cast<uint>(A[actr + (11 * j) + 1]) & 0x07) << 8)) * MLWE_Q) + 1024) >> 11;
				R[i][(8 * j) + 1] = ((((A[actr + (11 * j) + 1] >> 3) | ((static_cast<uint>(A[actr + (11 * j) + 2]) & 0x3F) << 5)) * MLWE_Q) + 1024) >> 11;
				R[i][(8 * j) + 2] = ((((A[actr + (11 * j) + 2] >> 6) | ((static_cast<uint>(A[actr + (11 * j) + 3]) & 0xFF) << 2) | ((static_cast<uint>(A[actr + (11 * j) + 4]) & 0x01) << 10)) * MLWE_Q) + 1024) >> 11;
				R[i][(8 * j) + 3] = ((((A[actr + (11 * j) + 4] >> 1) | ((static_cast<uint>(A[actr + (11 * j) + 5]) & 0x0F) << 7)) * MLWE_Q) + 1024) >> 11;
				R[i][(8 * j) + 4] = ((((A[actr + (11 * j) + 5] >> 4) | ((static_cast<uint>(A[actr + (11 * j) + 6]) & 0x7F) << 4)) * MLWE_Q) + 1024) >> 11;
				R[i][(8 * j) + 5] = ((((A[actr + (11 * j) + 6] >> 7) | ((static_cast<uint>(A[actr + (11 * j) + 7]) & 0xFF) << 1) | ((static_cast<uint>(A[actr + (11 * j) + 8]) & 0x03) << 9)) * MLWE_Q) + 1024) >> 11;
				R[i][(8 * j) + 6] = ((((A[actr + (11 * j) + 8] >> 2) | ((static_cast<uint>(A[actr + (11 * j) + 9]) & 0x1F) << 6)) * MLWE_Q) + 1024) >> 11;
				R[i][(8 * j) + 7] = ((((A[actr + (11 * j) + 9] >> 5) | ((static_cast<uint>(A[actr + (11 * j) + 10]) & 0xFF) << 3)) * MLWE_Q) + 1024) >> 11;
			}

			actr += PLYBSE;
		}
	}
	else
	{
		for (i = 0; i < R.size(); ++i)
		{
			for (j = 0; j < MLWE_N / 4; ++j)
			{
				R[i][4 * j] = (((A[actr + (5 * j)] | ((static_cast<uint>(A[actr + (5 * j) + 1]) & 0x03) << 8)) * MLWE_Q) + 512) >> 10;
				R[i][(4 * j) + 1] = ((((A[actr + (5 * j) + 1] >> 2) | ((static_cast<uint>(A[actr + (5 * j) + 2]) & 0x0F) << 6)) * MLWE_Q) + 512) >> 10;
				R[i][(4 * j) + 2] = ((((A[actr + (5 * j) + 2] >> 4) | ((static_cast<uint>(A[actr + (5 * j) + 3]) & 0x3F) << 4)) * MLWE_Q) + 512) >> 10;
				R[i][(4 * j) + 3] = ((((A[actr + (5 * j) + 3] >> 6) | ((static_cast<uint>(A[actr + (5 * j) + 4]) & 0xFF) << 2)) * MLWE_Q) + 512) >> 10;
			}

			actr += PLYBSE;
		}
	}
}

void MLWEQ3329N256::PolyVecToBytes(std::vector<byte> & R, std::vector<std::array<ushort, MLWE_N>> & A)
{
	size_t i;

	for (i = 0; i < A.size(); ++i)
	{
		PolyToBytes(R, i * MLWE_POLY_SIZE, A[i]);
	}
}

void MLWEQ3329N256::PolyVecFromBytes(std::vector<std::array<ushort, MLWE_N>> & R, const std::vector<byte> & A)
{
	size_t i;

	for (i = 0; i < R.size(); ++i)
	{
		PolyFromBytes(R[i], A, i * MLWE_POLY_SIZE);
	}
}

void MLWEQ3329N256::PolyVecNtt(std::vector<std::array<ushort, MLWE_N>> & R)
{
	size_t i;

	for (i = 0; i < R.size(); ++i)
	{
		PolyNtt(R[i]);
	}
}

void MLWEQ3329N256::PolyVecInvNtt(std::vector<std::array<ushort, MLWE_N>> & R)
{
	size_t i;

	for (i = 0; i < R.size(); ++i)
	{
		PolyInvNtt(R[i]);
	}
}

void MLWEQ3329N256::PolyVecPointwiseAcc(std::array<ushort, MLWE_N> & R, const std::vector<std::array<ushort, MLWE_N>> & A, const std::vector<std::array<ushort, MLWE_N>> & B)
{
	std::array<ushort, MLWE_N> t;
	size_t i;

	PolyBaseMul(R, A[0], B[0]);

	for (i = 1; i < A.size(); ++i)
	{
		PolyBaseMul(t, A[i], B[i]);
		PolyAdd(R, R, t);
	}

	PolyReduce(R);
}

void MLWEQ3329N256::PolyVecReduce(std::vector<std::array<ushort, MLWE_N>> & R)
{
	size_t i;

	for (i = 0; i < R.size(); ++i)
	{
		PolyReduce(R[i]);
	}
}

void MLWEQ3329N256::PolyVecCSubQ(std::vector<std::array<ushort, MLWE_N>> & R)
{
	size_t i;

	for (i = 0; i < R.size(); ++i)
	{
		PolyCSubQ(R[i]);
	}
}

void MLWEQ3329N256::PolyVecAdd(std::vector<std::array<ushort, MLWE_N>> & R, const std::vector<std::array<ushort, MLWE_N>> & A, const std::vector<std::array<ushort, MLWE_N>> & B)
{
	size_t i;

	for (i = 0; i < R.size(); ++i)
	{
		PolyAdd(R[i], A[i], B[i]);
	}
}

// reduce.c //

ushort MLWEQ3329N256::MontgomeryReduce(int32_t A)
{
	int32_t t;
	int16_t u;

	u = static_cast<int16_t>(A * MLWE_QINV);
	t = static_cast<int32_t>(u * MLWE_Q);
	t = A - t;
	t >>= 16;

	return static_cast<ushort>(t);
}

ushort MLWEQ3329N256::BarrettReduce(int16_t A)
{
	const int32_t V = (1U << 26) / MLWE_Q + 1;
	int32_t t;

	t = V * A;
	t >>= 26;
	t *= MLWE_Q;

	return static_cast<ushort>(A - t);
}

ushort MLWEQ3329N256::CSubQ(int16_t A)
{
	A -= MLWE_Q;
	A += (A >> 15) & MLWE_Q;

	return static_cast<ushort>(A);
}

void MLWEQ3329N256::Compute(const std::vector<byte> & Input, size_t InOffset, size_t InLength, std::vector<byte> & Output, size_t OutOffset, size_t OutLength, size_t Rate)
{
	std::array<ulong, Keccak::KECCAK_STATE_SIZE> state = { 0 };

	Keccak::AbsorbR24(Input, InOffset, InLength, Rate, Keccak::KECCAK_SHA3_DOMAIN, state);

#if defined(CEX_DIGEST_COMPACT)
	Keccak::PermuteR24P1600C(state);
#else
	Keccak::PermuteR24P1600U(state);
#endif

	MemoryTools::Copy(state, 0, Output, OutOffset, OutLength);
}

void MLWEQ3329N256::XOF(const std::vector<byte> & Input, size_t InOffset, size_t InLength, std::vector<byte> & Output, size_t OutOffset, size_t OutLength, size_t Rate)
{
	Keccak::XOFP1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
}

NAMESPACE_MODULELWEEND
