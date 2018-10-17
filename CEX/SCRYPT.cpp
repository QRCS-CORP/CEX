#include "SCRYPT.h"
#include "DigestFromName.h"
#include "Intrinsics.h"
#include "IntUtils.h"
#include "PBKDF2.h"
#include "ParallelUtils.h"
#include "SymmetricKey.h"

NAMESPACE_KDF

const std::string SCRYPT::CLASS_NAME("SCRYPT");

//~~~Constructor~~~//

SCRYPT::SCRYPT(SHA2Digests DigestType, size_t CpuCost, size_t Parallelization)
	:
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_msgDigest(DigestType != SHA2Digests::None ? Helper::DigestFromName::GetInstance(static_cast<Digests>(DigestType)) :
		throw CryptoKdfException("SCRYPT:Ctor", "The digest type is not supported!")),
	m_msgDigestType(static_cast<Digests>(DigestType)),
	m_kdfKey(0),
	m_kdfSalt(0),
	m_legalKeySizes(0),
	m_parallelProfile(64, true, 2048, true),
	m_scryptParameters(CpuCost, Parallelization)
{
	if (CpuCost < 1024 || CpuCost % 1024 != 0)
	{
		throw CryptoKdfException("SCRYPT:Ctor", "The cpu cost must be greater than 1024 divisible by 1024!");
	}

	Scope();
}

SCRYPT::SCRYPT(IDigest* Digest, size_t CpuCost, size_t Parallelization)
	:
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_msgDigest(Digest->Enumeral() == Digests::SHA256 || Digest->Enumeral() == Digests::SHA512 ? Digest :
		throw CryptoKdfException("SCRYPT:Ctor", "The digest type is not supported!")),
	m_msgDigestType(m_msgDigest->Enumeral()),
	m_kdfKey(0),
	m_kdfSalt(0),
	m_legalKeySizes(0),
	m_parallelProfile(64, true, 2048, true),
	m_scryptParameters(CpuCost, Parallelization)
{
	if (CpuCost < 1024 || CpuCost % 1024 != 0)
	{
		throw CryptoKdfException("SCRYPT:Ctor", "The cpu cost must be greater than 1024 divisible by 1024!");
	}

	Scope();
}

SCRYPT::~SCRYPT()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isInitialized = false;
		m_msgDigestType = Digests::None;
		m_parallelProfile.Reset();
		m_scryptParameters.Reset();

		Utility::IntUtils::ClearVector(m_kdfKey);
		Utility::IntUtils::ClearVector(m_kdfSalt);
		Utility::IntUtils::ClearVector(m_legalKeySizes);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_msgDigest != nullptr)
			{
				m_msgDigest.reset(nullptr);
			}
		}
		else
		{
			if (m_msgDigest != nullptr)
			{
				m_msgDigest.release();
			}
		}
	}
}

//~~~Accessors~~~//

size_t &SCRYPT::CpuCost()
{
	return m_scryptParameters.CpuCost;
}

const Kdfs SCRYPT::Enumeral()
{
	return Kdfs::SCRYPT256;
}

const bool SCRYPT::IsInitialized()
{
	return m_isInitialized; 
}

const bool SCRYPT::IsParallel()
{ 
	return m_parallelProfile.IsParallel(); 
}

const size_t SCRYPT::MinKeySize() 
{ 
	return MIN_PASSLEN; 
}

std::vector<SymmetricKeySize> SCRYPT::LegalKeySizes() const 
{ 
	return m_legalKeySizes; 
};

const std::string SCRYPT::Name() 
{ 
	return CLASS_NAME + "-" + m_msgDigest->Name();
}

size_t &SCRYPT::Parallelization()
{
	return m_scryptParameters.Parallelization;
}

ParallelOptions &SCRYPT::ParallelProfile() 
{ 
	return m_parallelProfile;
}

//~~~Public Functions~~~//

size_t SCRYPT::Generate(std::vector<byte> &Output)
{
	if (!m_isInitialized)
	{
		throw CryptoKdfException("SCRYPT:Generate", "The generator has not been initialized!");
	}

	return Expand(Output, 0, Output.size());
}

size_t SCRYPT::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoKdfException("SCRYPT:Generate", "The generator has not been initialized!");
	}

	return Expand(Output, OutOffset, Length);
}

void SCRYPT::Initialize(ISymmetricKey &GenParam)
{
	if (GenParam.Key().size() < MIN_PASSLEN)
	{
		throw CryptoKdfException("SCRYPT:Initialize", "Key size is too small; must be a minumum of 4 bytes!");
	}

	if (GenParam.Nonce().size() != 0)
	{
		if (GenParam.Info().size() != 0)
		{
			Initialize(GenParam.Key(), GenParam.Nonce(), GenParam.Info());
		}
		else
		{
			Initialize(GenParam.Key(), GenParam.Nonce());
		}
	}
	else
	{
		Initialize(GenParam.Key());
	}
}

void SCRYPT::Initialize(const std::vector<byte> &Key)
{
	if (Key.size() < MIN_PASSLEN)
	{
		throw CryptoKdfException("SCRYPT:Initialize", "Key size is too small; must be a minumum of 4 bytes!");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	m_kdfKey.resize(Key.size());
	Utility::MemUtils::Copy(Key, 0, m_kdfKey, 0, m_kdfKey.size());
	m_isInitialized = true;
}

void SCRYPT::Initialize(const std::vector<byte> &Key, size_t Offset, size_t Length)
{
	if (Key.size() < MIN_PASSLEN)
	{
		throw CryptoKdfException("SCRYPT:Initialize", "Key size is too small; must be a minumum of 4 bytes!");
	}

	std::vector<byte> tmpK(Length);
	Utility::MemUtils::Copy(Key, Offset, tmpK, 0, Length);
	Initialize(tmpK);
}

void SCRYPT::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt)
{
	if (Key.size() < MIN_PASSLEN)
	{
		throw CryptoKdfException("SCRYPT:Initialize", "Key size is too small, must be a minumum of 4 bytes!");
	}
	if (Salt.size() < MIN_SALTLEN)
	{
		throw CryptoKdfException("SCRYPT:Initialize", "Salt size is too small, must be a minumum of 4 bytes!");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	m_kdfKey.resize(Key.size());
	Utility::MemUtils::Copy(Key, 0, m_kdfKey, 0, m_kdfKey.size());
	m_kdfSalt.resize(Salt.size());
	Utility::MemUtils::Copy(Salt, 0, m_kdfSalt, 0, m_kdfSalt.size());

	m_isInitialized = true;
}

void SCRYPT::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info)
{
	if (Key.size() < MIN_PASSLEN)
	{
		throw CryptoKdfException("SCRYPT:Initialize", "Key size is too small, must be a minumum of 4 bytes!");
	}
	if (Salt.size() + Info.size() < MIN_SALTLEN)
	{
		throw CryptoKdfException("SCRYPT:Initialize", "Salt with info size is too small, combined must be a minumum of 4 bytes!");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	m_kdfKey.resize(Key.size());
	Utility::MemUtils::Copy(Key, 0, m_kdfKey, 0, m_kdfKey.size());
	m_kdfSalt.resize(Salt.size() + Info.size());

	if (Salt.size() > 0)
	{
		Utility::MemUtils::Copy(Salt, 0, m_kdfSalt, 0, m_kdfSalt.size());
	}
	if (Info.size() > 0)
	{
		Utility::MemUtils::Copy(Info, 0, m_kdfSalt, Salt.size(), Info.size());
	}

	m_isInitialized = true;
}

void SCRYPT::ReSeed(const std::vector<byte> &Seed)
{
	if (Seed.size() < MIN_PASSLEN)
	{
		throw CryptoKdfException("SCRYPT:ReSeed", "Seed can not be less than 4 bytes in length!");
	}

	if (Seed.size() > m_kdfSalt.size())
	{
		m_kdfSalt.resize(Seed.size());
	}

	Utility::MemUtils::Copy(Seed, 0, m_kdfSalt, 0, Seed.size());
}

void SCRYPT::Reset()
{
	m_kdfKey.clear();
	m_kdfSalt.clear();
	m_isInitialized = false;
}

//~~~Private Functions~~~//

void SCRYPT::BlockMix(std::vector<uint> &State, std::vector<uint> &Y)
{
	std::vector<uint> X(16);
	Utility::MemUtils::Copy(State, State.size() - 16, X, 0, 16 * sizeof(uint));

	for (size_t i = 0; i < 2 * MEM_COST; i += 2)
	{
		Utility::MemUtils::XorBlock(State, i * 16, X, 0, X.size() * sizeof(uint));
		SalsaCore(X);
		Utility::MemUtils::Copy(X, 0, Y, i * 8, 16 * sizeof(uint));

		Utility::MemUtils::XorBlock(State, i * 16 + 16, X, 0, X.size() * sizeof(uint));
		SalsaCore(X);
		Utility::MemUtils::Copy(X, 0, Y, i * 8 + MEM_COST * 16, 16 * sizeof(uint));
	}

	Utility::MemUtils::Copy(Y, 0, State, 0, Y.size() * sizeof(uint));
}

size_t SCRYPT::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t MFLEN = MEM_COST * 128;
	const size_t KEYLEN = m_scryptParameters.Parallelization * MFLEN;
	const size_t SKLEN = KEYLEN >> 2;

	std::vector<byte> tmpK(KEYLEN);
	Extract(tmpK, 0, m_kdfKey, m_kdfSalt, tmpK.size());

	const size_t MFLWRD = MFLEN >> 2;
	const size_t PRLBLK = SKLEN / m_parallelProfile.ParallelMaxDegree();
	size_t ttlOff = 0;
	std::vector<uint> stateK(SKLEN);

#if defined(__AVX__)
	for (size_t k = 0; k < 2 * MEM_COST * m_scryptParameters.Parallelization; ++k)
	{
		for (size_t i = 0; i < 16; i++)
		{
			stateK[k * 16 + i] = Utility::IntUtils::LeBytesTo32(tmpK, (k * 16 + (i * 5 % 16)) * 4);
		}
	}
#else
	Utility::IntUtils::BlockToLe(tmpK, 0, stateK, 0, tmpK.size());
#endif

	if (!m_parallelProfile.IsParallel() && PRLBLK >= MFLWRD)
	{
		Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &stateK, PRLBLK, MFLWRD](size_t i)
		{
			for (size_t j = 0; j < PRLBLK; j += MFLWRD)
			{
				SMix(stateK, (i * PRLBLK) + j, m_scryptParameters.CpuCost);
			}
		});

		ttlOff = PRLBLK * m_parallelProfile.ParallelMaxDegree();
	}

	if (ttlOff != SKLEN)
	{
		for (size_t i = ttlOff; i < SKLEN; i += MFLWRD)
		{
			SMix(stateK, i, m_scryptParameters.CpuCost);
		}
	}

#if defined(__AVX__)
	for (size_t k = 0; k < 2 * MEM_COST * m_scryptParameters.Parallelization; ++k)
	{
		for (size_t i = 0; i < 16; i++)
		{
			Utility::IntUtils::Le32ToBytes(stateK[k * 16 + i], tmpK, (k * 16 + (i * 5 % 16)) * 4);
		}
	}
#else
	Utility::IntUtils::LeToBlock(stateK, 0, tmpK, 0, tmpK.size());
#endif

	Extract(Output, OutOffset, m_kdfKey, tmpK, Length);

	return Length;
}

void SCRYPT::Extract(std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Key, std::vector<byte> &Salt, size_t Length)
{
	Kdf::PBKDF2 kdf(m_msgDigest.get(), 1);
	kdf.Initialize(Key::Symmetric::SymmetricKey(Key, Salt));
	kdf.Generate(Output, OutOffset, Length);
}

#if defined(__AVX__)
void SCRYPT::SalsaCore(std::vector<uint> &State)
{
	__m128i X0, X1, X2, X3;
	__m128i T;

	X0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[0]));
	X1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[4]));
	X2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[8]));
	X3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[12]));
	std::vector<__m128i> B { X0, X1, X2, X3};

	for (size_t i = 0; i < 8; i += 2)
	{
		T = _mm_add_epi32(X0, X3);
		X1 = _mm_xor_si128(X1, _mm_slli_epi32(T, 7));
		X1 = _mm_xor_si128(X1, _mm_srli_epi32(T, 25));
		T = _mm_add_epi32(X1, X0);
		X2 = _mm_xor_si128(X2, _mm_slli_epi32(T, 9));
		X2 = _mm_xor_si128(X2, _mm_srli_epi32(T, 23));
		T = _mm_add_epi32(X2, X1);
		X3 = _mm_xor_si128(X3, _mm_slli_epi32(T, 13));
		X3 = _mm_xor_si128(X3, _mm_srli_epi32(T, 19));
		T = _mm_add_epi32(X3, X2);
		X0 = _mm_xor_si128(X0, _mm_slli_epi32(T, 18));
		X0 = _mm_xor_si128(X0, _mm_srli_epi32(T, 14));

		X1 = _mm_shuffle_epi32(X1, 0x93);
		X2 = _mm_shuffle_epi32(X2, 0x4E);
		X3 = _mm_shuffle_epi32(X3, 0x39);

		T = _mm_add_epi32(X0, X1);
		X3 = _mm_xor_si128(X3, _mm_slli_epi32(T, 7));
		X3 = _mm_xor_si128(X3, _mm_srli_epi32(T, 25));
		T = _mm_add_epi32(X3, X0);
		X2 = _mm_xor_si128(X2, _mm_slli_epi32(T, 9));
		X2 = _mm_xor_si128(X2, _mm_srli_epi32(T, 23));
		T = _mm_add_epi32(X2, X3);
		X1 = _mm_xor_si128(X1, _mm_slli_epi32(T, 13));
		X1 = _mm_xor_si128(X1, _mm_srli_epi32(T, 19));
		T = _mm_add_epi32(X1, X2);
		X0 = _mm_xor_si128(X0, _mm_slli_epi32(T, 18));
		X0 = _mm_xor_si128(X0, _mm_srli_epi32(T, 14));

		X1 = _mm_shuffle_epi32(X1, 0x39);
		X2 = _mm_shuffle_epi32(X2, 0x4E);
		X3 = _mm_shuffle_epi32(X3, 0x93);
	}

	_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[0]), _mm_add_epi32(B[0], X0));
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[4]), _mm_add_epi32(B[1], X1));
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[8]), _mm_add_epi32(B[2], X2));
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[12]), _mm_add_epi32(B[3], X3));
}

#else

void SCRYPT::SalsaCore(std::vector<uint> &State)
{
	uint X0 = State[0];
	uint X1 = State[1];
	uint X2 = State[2];
	uint X3 = State[3];
	uint X4 = State[4];
	uint X5 = State[5];
	uint X6 = State[6];
	uint X7 = State[7];
	uint X8 = State[8];
	uint X9 = State[9];
	uint X10 = State[10];
	uint X11 = State[11];
	uint X12 = State[12];
	uint X13 = State[13];
	uint X14 = State[14];
	uint X15 = State[15];

	size_t ctr = 8;
	while (ctr != 0)
	{
		X4 ^= Utility::IntUtils::RotFL32(X0 + X12, 7);
		X8 ^= Utility::IntUtils::RotFL32(X4 + X0, 9);
		X12 ^= Utility::IntUtils::RotFL32(X8 + X4, 13);
		X0 ^= Utility::IntUtils::RotFL32(X12 + X8, 18);
		X9 ^= Utility::IntUtils::RotFL32(X5 + X1, 7);
		X13 ^= Utility::IntUtils::RotFL32(X9 + X5, 9);
		X1 ^= Utility::IntUtils::RotFL32(X13 + X9, 13);
		X5 ^= Utility::IntUtils::RotFL32(X1 + X13, 18);
		X14 ^= Utility::IntUtils::RotFL32(X10 + X6, 7);
		X2 ^= Utility::IntUtils::RotFL32(X14 + X10, 9);
		X6 ^= Utility::IntUtils::RotFL32(X2 + X14, 13);
		X10 ^= Utility::IntUtils::RotFL32(X6 + X2, 18);
		X3 ^= Utility::IntUtils::RotFL32(X15 + X11, 7);
		X7 ^= Utility::IntUtils::RotFL32(X3 + X15, 9);
		X11 ^= Utility::IntUtils::RotFL32(X7 + X3, 13);
		X15 ^= Utility::IntUtils::RotFL32(X11 + X7, 18);
		X1 ^= Utility::IntUtils::RotFL32(X0 + X3, 7);
		X2 ^= Utility::IntUtils::RotFL32(X1 + X0, 9);
		X3 ^= Utility::IntUtils::RotFL32(X2 + X1, 13);
		X0 ^= Utility::IntUtils::RotFL32(X3 + X2, 18);
		X6 ^= Utility::IntUtils::RotFL32(X5 + X4, 7);
		X7 ^= Utility::IntUtils::RotFL32(X6 + X5, 9);
		X4 ^= Utility::IntUtils::RotFL32(X7 + X6, 13);
		X5 ^= Utility::IntUtils::RotFL32(X4 + X7, 18);
		X11 ^= Utility::IntUtils::RotFL32(X10 + X9, 7);
		X8 ^= Utility::IntUtils::RotFL32(X11 + X10, 9);
		X9 ^= Utility::IntUtils::RotFL32(X8 + X11, 13);
		X10 ^= Utility::IntUtils::RotFL32(X9 + X8, 18);
		X12 ^= Utility::IntUtils::RotFL32(X15 + X14, 7);
		X13 ^= Utility::IntUtils::RotFL32(X12 + X15, 9);
		X14 ^= Utility::IntUtils::RotFL32(X13 + X12, 13);
		X15 ^= Utility::IntUtils::RotFL32(X14 + X13, 18);
		ctr -= 2;
	}

	State[0] += X0;
	State[1] += X1;
	State[2] += X2;
	State[3] += X3;
	State[4] += X4;
	State[5] += X5;
	State[6] += X6;
	State[7] += X7;
	State[8] += X8;
	State[9] += X9;
	State[10] += X10;
	State[11] += X11;
	State[12] += X12;
	State[13] += X13;
	State[14] += X14;
	State[15] += X15;
}

#endif

void SCRYPT::Scope()
{
	// enable/disable multi-threading
	m_parallelProfile.IsParallel() = (m_scryptParameters.Parallelization != 1);

	// set the parallel factor or adjust thread count
	if (m_scryptParameters.Parallelization == 0)
	{
		// auto-set
		m_scryptParameters.Parallelization = m_parallelProfile.ParallelMaxDegree();
	}
	else if (m_scryptParameters.Parallelization > 1 && m_scryptParameters.Parallelization < m_parallelProfile.ParallelMaxDegree())
	{
		// custom degree
		m_parallelProfile.SetMaxDegree(m_scryptParameters.Parallelization);
	}

	m_legalKeySizes.resize(3);
	// this is the recommended size: 
	// ideally, salt should be passphrase len - (4 bytes of pbkdf counter + digest finalizer code)
	// you want to fill one complete block, and avoid hmac compression on > block-size
	m_legalKeySizes[0] = SymmetricKeySize(m_msgDigest->DigestSize(), 0, 0);
	// 2nd recommended size
	m_legalKeySizes[1] = SymmetricKeySize(m_msgDigest->BlockSize(), m_msgDigest->DigestSize(), 0);
	// max recommended
	m_legalKeySizes[2] = SymmetricKeySize(m_msgDigest->BlockSize(), m_msgDigest->BlockSize(), 0);
}

void SCRYPT::SMix(std::vector<uint> &State, size_t StateOffset, size_t N)
{
	size_t bCount = MEM_COST * 32;
	std::vector<uint> X(bCount);
	std::vector<uint> Y(bCount);
	std::vector<std::vector<uint>> V(N);

	Utility::MemUtils::Copy(State, StateOffset, X, 0, bCount * sizeof(uint));

	for (size_t i = 0; i < N; ++i)
	{
		V[i] = X;
		BlockMix(X, Y);
	}

	const uint NMASK = static_cast<uint>(N - 1);
	for (size_t i = 0; i < N; ++i)
	{
		uint j = X[bCount - 16] & NMASK;
		Utility::MemUtils::XorBlock(V[j], 0, X, 0, X.size() * sizeof(uint));
		BlockMix(X, Y);
	}

	Utility::MemUtils::Copy(X, 0, State, StateOffset, bCount * sizeof(uint));
}

NAMESPACE_KDFEND
