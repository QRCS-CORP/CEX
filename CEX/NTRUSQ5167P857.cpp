#include "NTRUSQ5167P857.h"

NAMESPACE_NTRUPRIME

bool NTRUSQ5167P857::Decapsulate(std::vector<byte> &Secret, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey)
{
	// k = Decap(c,sk)

	std::vector<byte> pk(PUBLICKEY_SIZE);
	std::vector<byte> rho(NTRUP_SPOLY);
	std::vector<byte> cache(SEED_SIZE);
	std::vector<int8_t> tmpr(NTRUP_P);
	std::vector<byte> renc(NTRUP_SPOLY);
	std::vector<byte> cnew(CipherText.size());
	size_t i;
	int32_t mask;

	MemoryTools::Copy(PrivateKey, NTRUP_CPAPRIVATEKEY_SIZE, pk, 0, PUBLICKEY_SIZE);
	MemoryTools::Copy(PrivateKey, NTRUP_CPAPRIVATEKEY_SIZE + PUBLICKEY_SIZE, rho, 0, NTRUP_SPOLY);
	MemoryTools::Copy(PrivateKey, NTRUP_CPAPRIVATEKEY_SIZE + PUBLICKEY_SIZE + NTRUP_SPOLY, cache, 0, NTRUP_HASH_SIZE);

	ZDecrypt(tmpr, CipherText, PrivateKey);
	Hide(cnew, renc, tmpr, pk, cache);
	mask = IntegerTools::DiffMask(CipherText, cnew, cnew.size());

	for (i = 0; i < NTRUP_SPOLY; ++i)
	{
		renc[i] ^= mask & (renc[i] ^ rho[i]);
	}

	HashSession(Secret, 1 + mask, renc, CipherText);

	return (mask == 0);
}

void NTRUSQ5167P857::Encapsulate(std::vector<byte> &Secret, std::vector<byte> &CipherText, const std::vector<byte> &PublicKey, std::unique_ptr<Prng::IPrng> &Rng)
{
	// c,k = Encap(pk)

	std::vector<int8_t> tmpr(NTRUP_P);
	std::vector<byte> renc(NTRUP_SPOLY);
	std::vector<byte> cache(NTRUP_HASH_SIZE);

	Hash(cache, 0, 4, PublicKey);
	ShortRandom(tmpr, Rng);
	Hide(CipherText, renc, tmpr, PublicKey, cache);
	HashSession(Secret, 1, renc, CipherText);
}

void NTRUSQ5167P857::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
{
	ZKeyGen(PublicKey, PrivateKey, Rng);
	MemoryTools::Copy(PublicKey, 0, PrivateKey, NTRUP_CPAPRIVATEKEY_SIZE, PUBLICKEY_SIZE);
	Rng->Generate(PrivateKey, NTRUP_CPAPRIVATEKEY_SIZE + PUBLICKEY_SIZE, NTRUP_SPOLY);
	Hash(PrivateKey, NTRUP_CPAPRIVATEKEY_SIZE + PUBLICKEY_SIZE + NTRUP_SPOLY, 4, PublicKey);
}

void NTRUSQ5167P857::Hash(std::vector<byte> &Output, size_t OutOffset, int B, const std::vector<byte> &Input)
{
	// e.g., b = 0 means out = Hash0(in)

	std::vector<byte> x(Input.size() + 1);
	std::vector<byte> h(64);

	x[0] = B;
	MemoryTools::Copy(Input, 0, x, 1, Input.size());

	SHA512 dgt;
	dgt.Compute(x, h);
	MemoryTools::Copy(h, 0, Output, OutOffset, NTRUP_HASH_SIZE);
}

void NTRUSQ5167P857::HashConfirm(std::vector<byte> &H, size_t HOffset, const std::vector<byte> &R, const std::vector<byte> &Pk, const std::vector<byte> &Cache) // is pk supposed to be hashed here?
{
	// h = HashConfirm(r,pk,cache); cache is Hash4(pk)

	std::vector<byte> x(NTRUP_HASH_SIZE * 2);

	Hash(x, 0, 3, R);
	MemoryTools::Copy(Cache, 0, x, NTRUP_HASH_SIZE, NTRUP_HASH_SIZE);
	Hash(H, HOffset, 2, x);
}

void NTRUSQ5167P857::HashSession(std::vector<byte> &K, int B, const std::vector<byte> &Y, const std::vector<byte> &Z)
{
	// k = HashSession(b,y,z)

	std::vector<byte> x(Z.size() + NTRUP_HASH_SIZE);

	Hash(x, 0, 3, Y);
	MemoryTools::Copy(Z, 0, x, NTRUP_HASH_SIZE, Z.size());
	Hash(K, 0, B, x);
}

void NTRUSQ5167P857::Hide(std::vector<byte> &C, std::vector<byte> &REnc, const std::vector<int8_t> &R, const std::vector<byte> &Pk, const std::vector<byte> &Cache)
{
	// c,renc = Hide(r,pk,cache); cache is Hash4(pk)

	NTRUPolyMath::SmallEncode(REnc, 0, R);
	ZEncrypt(C, R, Pk);

	HashConfirm(C, C.size() - NTRUP_HASH_SIZE, REnc, Pk, Cache);
}

void NTRUSQ5167P857::KeyGen(std::vector<int16_t> &H, std::vector<int8_t> &F, std::vector<int8_t> &GInv, std::unique_ptr<Prng::IPrng> &Rng)
{
	// h,(f,ginv) = KeyGen()

	std::vector<int8_t> g(H.size());
	std::vector<int16_t> finv(H.size());

	while (true)
	{
		SmallRandom(g, Rng);

		if (NTRUPolyMath::R3Recip(GInv, g) == 0)
		{
			break;
		}
	}

	ShortRandom(F, Rng);
	// always works
	NTRUPolyMath::RqRecip3(finv, F, NTRUP_Q);
	NTRUPolyMath::RqMultSmall(H, finv, g, NTRUP_Q);
}

void NTRUSQ5167P857::ShortFromList(std::vector<int8_t> &Output, const std::vector<uint> &Input)
{
	std::vector<uint> tmpl(NTRUP_P);
	size_t i;

	for (i = 0; i < NTRUP_W; ++i)
	{
		tmpl[i] = Input[i] & (~2 + 1);
	}

	for (i = NTRUP_W; i < NTRUP_P; ++i)
	{
		tmpl[i] = (Input[i] & (~3 + 1)) | 1;
	}

	NTRUPolyMath::U32Sort(tmpl, NTRUP_P);

	for (i = 0; i < NTRUP_P; ++i)
	{
		Output[i] = (tmpl[i] & 3) - 1;
	}
}

void NTRUSQ5167P857::ShortRandom(std::vector<int8_t> &Output, std::unique_ptr<Prng::IPrng> &Rng)
{
	std::vector<uint> tmpl(Output.size());
	size_t i;

	for (i = 0; i < tmpl.size(); ++i)
	{
		tmpl[i] = URandom32(Rng);
	}

	ShortFromList(Output, tmpl);
}

void NTRUSQ5167P857::SmallRandom(std::vector<int8_t> &Output, std::unique_ptr<Prng::IPrng> &Rng)
{
	size_t i;

	for (i = 0; i < Output.size(); ++i)
	{
		Output[i] = (((URandom32(Rng) & 0x3FFFFFFFUL) * 3) >> 30) - 1;
	}
}

uint NTRUSQ5167P857::URandom32(std::unique_ptr<Prng::IPrng> &Rng)
{
	std::vector<byte> rnd(4);
	uint x;

	Rng->Generate(rnd);

	x = static_cast<uint>(rnd[0]) +
		(static_cast<uint>(rnd[1]) << 8) +
		(static_cast<uint>(rnd[2]) << 16) +
		(static_cast<uint>(rnd[3]) << 24);

	return x;
}

void NTRUSQ5167P857::ZKeyGen(std::vector<byte> &Pk, std::vector<byte> &Sk, std::unique_ptr<Prng::IPrng> &Rng)
{
	// pk,sk = ZKeyGen() 

	std::vector<int16_t> h(NTRUP_P);
	std::vector<int8_t> f(NTRUP_P);
	std::vector<int8_t> v(NTRUP_P);

	KeyGen(h, f, v, Rng);
	NTRUPolyMath::RqEncode(Pk, h, NTRUP_Q);
	NTRUPolyMath::SmallEncode(Sk, 0, f);
	NTRUPolyMath::SmallEncode(Sk, NTRUP_SPOLY, v);
}

void NTRUSQ5167P857::ZDecrypt(std::vector<int8_t> &R, const std::vector<byte> &C, const std::vector<byte> &Sk)
{
	// r = ZDecrypt(C,sk)

	std::vector<int16_t> tmpc(NTRUP_P);
	std::vector<int8_t> tmpf(NTRUP_P);
	std::vector<int8_t> tmpv(NTRUP_P);

	NTRUPolyMath::SmallDecode(tmpf, Sk, 0);
	NTRUPolyMath::SmallDecode(tmpv, Sk, NTRUP_SPOLY);
	NTRUPolyMath::RoundedDecode(tmpc, C, NTRUP_Q);
	NTRUPolyMath::Decrypt(R, tmpc, tmpf, tmpv, NTRUP_Q, NTRUP_W);
}

void NTRUSQ5167P857::ZEncrypt(std::vector<byte> &C, const std::vector<int8_t> &R, const std::vector<byte> &Pk)
{
	// C = ZEncrypt(r,pk)

	std::vector<int16_t> tmph(R.size());
	std::vector<int16_t> tmpc(R.size());

	NTRUPolyMath::RqDecode(tmph, Pk, NTRUP_Q);
	NTRUPolyMath::Encrypt(tmpc, R, tmph, NTRUP_Q);
	NTRUPolyMath::RoundedEncode(C, tmpc, NTRUP_Q);
}

NAMESPACE_NTRUPRIMEEND
