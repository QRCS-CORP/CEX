#include "THX.h"
#include "Twofish.h"
#include "DigestFromName.h"
#include "HKDF.h"
#include "IntUtils.h"
#include "MemUtils.h"
#if defined(CEX_COMPILER_MSC)
#	if defined(__AVX512__)
#		include "UInt512.h"
#	elif defined(__AVX2__)
#		include "UInt256.h"
#	elif defined(__AVX__)
#		include "UInt128.h"
#	endif
#endif

NAMESPACE_BLOCK

const std::string THX::CIPHER_NAME("Twofish");
const std::string THX::CLASS_NAME("THX");
const std::string THX::DEF_DSTINFO("THX version 1 information string");

//~~~Properties~~~//

const size_t THX::BlockSize()
{
	return BLOCK_SIZE;
}

std::vector<byte> &THX::DistributionCode()
{
	return m_kdfInfo;
}

const size_t THX::DistributionCodeMax()
{
	return m_kdfInfoMax;
}

const BlockCiphers THX::Enumeral()
{
	return (m_kdfEngineType == Digests::None) ? BlockCiphers::Twofish : BlockCiphers::THX;
}

const bool THX::IsEncryption()
{
	return m_isEncryption;
}

const bool THX::IsInitialized()
{
	return m_isInitialized;
}

const Digests THX::KdfEngine()
{
	return m_kdfEngineType;
}

const std::vector<SymmetricKeySize> &THX::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::vector<size_t> &THX::LegalRounds()
{
	return m_legalRounds;
}

const std::string THX::Name()
{
	if (m_kdfEngineType == Digests::None)
		return CIPHER_NAME + (m_cprKeySize != 0 ? Utility::IntUtils::ToString(m_cprKeySize) : "");
	else
		return CLASS_NAME + (m_cprKeySize != 0 ? Utility::IntUtils::ToString(m_cprKeySize) : "");
}

const size_t THX::Rounds()
{
	return m_rndCount;
}

const size_t THX::StateCacheSize()
{
	return STATE_PRECACHED;
}

//~~~Constructor~~~//

THX::THX(Digests KdfEngineType, uint Rounds)
	:
	m_cprKeySize(0),
	m_destroyEngine(true),
	m_expKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_kdfEngine(KdfEngineType == Digests::None ? 0 : Helper::DigestFromName::GetInstance(KdfEngineType)),
	m_kdfEngineType(KdfEngineType),
	m_kdfInfo(DEF_DSTINFO.begin(), DEF_DSTINFO.end()),
	m_kdfInfoMax(0),
	m_kdfKeySize(0),
	m_legalKeySizes(0),
	m_legalRounds(0),
	m_rndCount(Rounds),
	m_sBox(SBOX_SIZE, 0)
{
	if (KdfEngineType != Digests::None && Rounds != 16 && Rounds != 18 && Rounds != 20 && Rounds != 22 && Rounds != 24 && Rounds != 26 && Rounds != 28 && Rounds != 30 && Rounds != 32)
			throw CryptoSymmetricCipherException("THX:CTor", "Invalid rounds size! Sizes supported are 16, 18, 20, 22, 24, 26, 28, 30 and 32.");

	LoadState(KdfEngineType);
}

THX::THX(IDigest *KdfEngine, size_t Rounds)
	:
	m_cprKeySize(0),
	m_destroyEngine(false),
	m_expKey(0),
	m_isDestroyed(false),
	m_isEncryption(false),
	m_isInitialized(false),
	m_kdfEngine(KdfEngine),
	m_kdfEngineType(m_kdfEngine != 0 ? KdfEngine->Enumeral() : Digests::None),
	m_kdfInfo(DEF_DSTINFO.begin(), DEF_DSTINFO.end()),
	m_kdfInfoMax(0),
	m_kdfKeySize(0),
	m_legalKeySizes(0),
	m_legalRounds(0),
	m_rndCount(Rounds),
	m_sBox(SBOX_SIZE, 0)
{
	if (Rounds != 16 && Rounds != 18 && Rounds != 20 && Rounds != 22 && Rounds != 24 && Rounds != 26 && Rounds != 28 && Rounds != 30 && Rounds != 32)
		throw CryptoSymmetricCipherException("THX:CTor", "Invalid rounds size! Sizes supported are 16, 18, 20, 22, 24, 26, 28, 30 and 32.");

	LoadState(KdfEngine->Enumeral());
}

THX::~THX()
{
	Destroy();
}

//~~~Public Functions~~~//

void THX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void THX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void THX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void THX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void THX::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_cprKeySize = 0;
		m_isEncryption = false;
		m_isInitialized = false;
		m_kdfEngineType = Digests::None;
		m_kdfInfoMax = 0;
		m_kdfKeySize = 0;
		m_rndCount = 0;

		try
		{
			Utility::IntUtils::ClearVector(m_expKey);
			Utility::IntUtils::ClearVector(m_sBox);
			Utility::IntUtils::ClearVector(m_kdfInfo);
			Utility::IntUtils::ClearVector(m_legalKeySizes);
			Utility::IntUtils::ClearVector(m_legalRounds);

			if (m_kdfEngine != 0 && m_destroyEngine)
				delete m_kdfEngine;

			m_destroyEngine = false;
		}
		catch (std::exception& ex)
		{
			throw CryptoSymmetricCipherException("THX:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

void THX::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(m_legalKeySizes, KeyParams.Key().size()))
		throw CryptoSymmetricCipherException("THX:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	if (m_kdfEngineType != Enumeration::Digests::None && KeyParams.Info().size() > m_kdfInfoMax)
		throw CryptoSymmetricCipherException("THX:Initialize", "Invalid info size! Info parameter must be no longer than DistributionCodeMax size.");

	if (KeyParams.Info().size() > 0)
		m_kdfInfo = KeyParams.Info();

	m_isEncryption = Encryption;
	m_cprKeySize = KeyParams.Key().size() * 8;
	// expand the key
	ExpandKey(KeyParams.Key());

	// load tables into L1
#if defined(CEX_PREFETCH_THX_TABLES)
	Prefetch();
#endif
	// ready to transform data
	m_isInitialized = true;
}

void THX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (m_isEncryption)
		Encrypt128(Input, 0, Output, 0);
	else
		Decrypt128(Input, 0, Output, 0);
}

void THX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt128(Input, InOffset, Output, OutOffset);
	else
		Decrypt128(Input, InOffset, Output, OutOffset);
}

void THX::Transform512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt512(Input, InOffset, Output, OutOffset);
	else
		Decrypt512(Input, InOffset, Output, OutOffset);
}

void THX::Transform1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt1024(Input, InOffset, Output, OutOffset);
	else
		Decrypt1024(Input, InOffset, Output, OutOffset);
}

void THX::Transform2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt2048(Input, InOffset, Output, OutOffset);
	else
		Decrypt2048(Input, InOffset, Output, OutOffset);
}

//~~~Key Schedule~~~//

void THX::ExpandKey(const std::vector<byte> &Key)
{
	if (m_kdfEngineType != Enumeration::Digests::None)
	{
		// hkdf key expansion
		SecureExpand(Key);
	}
	else
	{
		// standard rijndael key expansion + k512
		StandardExpand(Key);
	}
}

void THX::SecureExpand(const std::vector<byte> &Key)
{
	// ToDo: look into some changes
	// 1) Pull the sbox key directly from the kdf and remove(?) sbox premix stage
	// 2) Store sbox key and calculate sbox member on the fly when sse/avx enabled(?) test performance
	// 3) If (2) is a significant gain, sbox becomes fallback when intrinsics are not available

	size_t k64Cnt = 4;
	size_t keyCtr = 0;
	size_t keySize = m_rndCount * 2 + 8;
	size_t keyBytes = keySize * 4;
	std::vector<byte> sbKey(16, 0);
	std::vector<uint> eKm(k64Cnt, 0);
	std::vector<uint> oKm(k64Cnt, 0);
	std::vector<uint> wK(keySize, 0);

	Kdf::HKDF gen(m_kdfEngine);

	// change 1.2: use extract only on an oversized key
	if (Key.size() > m_kdfEngine->BlockSize())
	{
		// seperate salt and key
		m_kdfKeySize = m_kdfEngine->BlockSize();
		std::vector<byte> kdfKey(m_kdfKeySize, 0);
		Utility::MemUtils::Copy<byte>(Key, 0, kdfKey, 0, m_kdfKeySize);
		size_t saltSize = Key.size() - m_kdfKeySize;
		std::vector<byte> kdfSalt(saltSize, 0);
		Utility::MemUtils::Copy<byte>(Key, m_kdfKeySize, kdfSalt, 0, saltSize);
		// info can be null
		gen.Initialize(kdfKey, kdfSalt, m_kdfInfo);
	}
	else
	{
		if (m_kdfInfo.size() != 0)
			gen.Info() = m_kdfInfo;

		gen.Initialize(Key);
	}

	std::vector<byte> rawKey(keyBytes, 0);
	// expand the round keys
	gen.Generate(rawKey);
	// initialize working key
	m_expKey.resize(keySize, 0);
	// copy bytes to working key
	for (size_t i = 0; i < wK.size(); ++i)
		wK[i] = Utility::IntUtils::LeBytesTo32(rawKey, i * sizeof(uint));

	// sbox encoding steps
	for (uint i = 0; i < k64Cnt; i++)
	{
		// round key material
		eKm[i] = Utility::IntUtils::LeBytesTo32(rawKey, keyCtr);
		keyCtr += 4;
		oKm[i] = Utility::IntUtils::LeBytesTo32(rawKey, keyCtr);
		keyCtr += 4;
		// sbox key material
		Utility::IntUtils::Le32ToBytes(MdsEncode(eKm[i], oKm[i]), sbKey, ((k64Cnt * 4) - 4) - (i * 4));
	}

	keyCtr = 0;
	std::vector<uint> sMix(4);

	while (keyCtr != KEY_BITS)
	{
		Mix16((uint)keyCtr, sbKey, Key.size(), sMix);
		m_sBox[keyCtr * 2] = sMix[0];
		m_sBox[keyCtr * 2 + 1] = sMix[1];
		m_sBox[keyCtr * 2 + 0x200] = sMix[2];
		m_sBox[keyCtr * 2 + 0x201] = sMix[3];
		++keyCtr;
	}

	m_expKey = wK;
}

void THX::StandardExpand(const std::vector<byte> &Key)
{
	size_t k64Cnt = (Key.size() / 8);
	size_t kmLen = k64Cnt > 4 ? 8 : 4;
	size_t keyCtr = 0;
	uint A, B, Q;
	std::vector<uint> eKm(kmLen, 0);
	std::vector<uint> oKm(kmLen, 0);
	std::vector<byte> sbKey(Key.size() == 64 ? 32 : 16, 0);
	std::vector<uint> wK(m_rndCount * 2 + 8, 0);

	// CHANGE: 512 key gets 4 extra rounds
	m_rndCount = (Key.size() == 64) ? 20 : DEF_ROUNDS;

	for (size_t i = 0; i < k64Cnt; ++i)
	{
		// round key material
		eKm[i] = Utility::IntUtils::LeBytesTo32(Key, keyCtr);
		keyCtr += 4;
		oKm[i] = Utility::IntUtils::LeBytesTo32(Key, keyCtr);
		keyCtr += 4;
		// sbox key material
		Utility::IntUtils::Le32ToBytes(MdsEncode(eKm[i], oKm[i]), sbKey, ((k64Cnt * 4) - 4) - (i * 4));
	}

	// gen s-box members
	keyCtr = 0;
	std::vector<uint> sMix(4);

	while (keyCtr != KEY_BITS)
	{
		// create the expanded key
		if (keyCtr < (wK.size() / 2))
		{
			Q = (uint)(keyCtr * SK_STEP);
			A = Mix4(Q, eKm, k64Cnt);
			B = Mix4(Q + SK_BUMP, oKm, k64Cnt);
			B = B << 8 | (uint)(B >> 24);
			A += B;
			wK[keyCtr * 2] = A;
			A += B;
			wK[(keyCtr * 2) + 1] = (uint)(A << SK_ROTL) | (uint)(A >> (32 - SK_ROTL));
		}

		Mix16((uint)keyCtr, sbKey, Key.size(), sMix);
		m_sBox[keyCtr * 2] = sMix[0];
		m_sBox[keyCtr * 2 + 1] = sMix[1];
		m_sBox[keyCtr * 2 + 0x200] = sMix[2];
		m_sBox[keyCtr * 2 + 0x201] = sMix[3];
		++keyCtr;
	}

	m_expKey = wK;
}

//~~~Rounds Processing~~~//

void THX::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t FNLRND = 8;
	size_t keyCtr = 4;
	uint X2 = Utility::IntUtils::LeBytesTo32(Input, InOffset) ^ m_expKey[keyCtr];
	uint X3 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 4) ^ m_expKey[++keyCtr];
	uint X0 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 8) ^ m_expKey[++keyCtr];
	uint X1 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 12) ^ m_expKey[++keyCtr];
	uint T0, T1;

	keyCtr = m_expKey.size();
	do
	{
		T0 = Fe0(X2, m_sBox);
		T1 = Fe3(X3, m_sBox);
		X1 ^= T0 + 2 * T1 + m_expKey[--keyCtr];
		X0 = (X0 << 1) | (X0 >> 31);
		X0 ^= (T0 + T1 + m_expKey[--keyCtr]);
		X1 = (X1 >> 1) | (X1 << 31);

		T0 = Fe0(X0, m_sBox);
		T1 = Fe3(X1, m_sBox);
		X3 ^= T0 + 2 * T1 + m_expKey[--keyCtr];
		X2 = (X2 << 1) | (X2 >> 31);
		X2 ^= (T0 + T1 + m_expKey[--keyCtr]);
		X3 = (X3 >> 1) | (X3 << 31);
	} 
	while (keyCtr != FNLRND);

	keyCtr = 0;
	Utility::IntUtils::Le32ToBytes(X0 ^ m_expKey[keyCtr], Output, OutOffset);
	Utility::IntUtils::Le32ToBytes(X1 ^ m_expKey[++keyCtr], Output, OutOffset + 4);
	Utility::IntUtils::Le32ToBytes(X2 ^ m_expKey[++keyCtr], Output, OutOffset + 8);
	Utility::IntUtils::Le32ToBytes(X3 ^ m_expKey[++keyCtr], Output, OutOffset + 12);
}

void THX::Decrypt512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if !defined(__AVX512__) && !defined(__AVX2__) && defined(__AVX__) && defined(CEX_COMPILER_MSC)
	THXDecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
#else
	Decrypt128(Input, InOffset, Output, OutOffset);
	Decrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt128(Input, InOffset + 48, Output, OutOffset + 48);
#endif
}

void THX::Decrypt1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if !defined(__AVX512__) && defined(__AVX2__) && defined(CEX_COMPILER_MSC)
	THXDecryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
#elif !defined(__AVX512__) && !defined(__AVX2__) && defined(__AVX__) && defined(CEX_COMPILER_MSC)
	THXDecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
	THXDecryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey, m_sBox);
#else
	Decrypt128(Input, InOffset, Output, OutOffset);
	Decrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt128(Input, InOffset + 48, Output, OutOffset + 48);
	Decrypt128(Input, InOffset + 64, Output, OutOffset + 64);
	Decrypt128(Input, InOffset + 80, Output, OutOffset + 80);
	Decrypt128(Input, InOffset + 96, Output, OutOffset + 96);
	Decrypt128(Input, InOffset + 112, Output, OutOffset + 112);
#endif
}

void THX::Decrypt2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(__AVX512__) && defined(CEX_COMPILER_MSC)
	THXDecryptW<Numeric::UInt512>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
#elif !defined(__AVX512__) && defined(__AVX2__) && defined(CEX_COMPILER_MSC)
	THXDecryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
	THXDecryptW<Numeric::UInt256>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey, m_sBox);
#elif !defined(__AVX512__) && !defined(__AVX2__) && defined(__AVX__) && defined(CEX_COMPILER_MSC)
	THXDecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
	THXDecryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey, m_sBox);
	THXDecryptW<Numeric::UInt128>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey, m_sBox);
	THXDecryptW<Numeric::UInt128>(Input, InOffset + 192, Output, OutOffset + 192, m_expKey, m_sBox);
#else
	Decrypt128(Input, InOffset, Output, OutOffset);
	Decrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt128(Input, InOffset + 48, Output, OutOffset + 48);
	Decrypt128(Input, InOffset + 64, Output, OutOffset + 64);
	Decrypt128(Input, InOffset + 80, Output, OutOffset + 80);
	Decrypt128(Input, InOffset + 96, Output, OutOffset + 96);
	Decrypt128(Input, InOffset + 112, Output, OutOffset + 112);
	Decrypt128(Input, InOffset + 128, Output, OutOffset + 128);
	Decrypt128(Input, InOffset + 144, Output, OutOffset + 144);
	Decrypt128(Input, InOffset + 160, Output, OutOffset + 160);
	Decrypt128(Input, InOffset + 176, Output, OutOffset + 176);
	Decrypt128(Input, InOffset + 192, Output, OutOffset + 192);
	Decrypt128(Input, InOffset + 208, Output, OutOffset + 208);
	Decrypt128(Input, InOffset + 224, Output, OutOffset + 224);
	Decrypt128(Input, InOffset + 240, Output, OutOffset + 240);
#endif
}

void THX::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t FNLRND = m_expKey.size() - 1;
	size_t keyCtr = 0;
	uint X0 = Utility::IntUtils::LeBytesTo32(Input, InOffset) ^ m_expKey[keyCtr];
	uint X1 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 4) ^ m_expKey[++keyCtr];
	uint X2 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 8) ^ m_expKey[++keyCtr];
	uint X3 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 12) ^ m_expKey[++keyCtr];
	uint T0, T1;

	keyCtr = 7;
	do
	{
		T0 = Fe0(X0, m_sBox);
		T1 = Fe3(X1, m_sBox);
		X2 ^= T0 + T1 + m_expKey[++keyCtr];
		X2 = (X2 >> 1) | (X2 << 31);
		X3 = (X3 << 1) | (X3 >> 31);
		X3 ^= (T0 + 2 * T1 + m_expKey[++keyCtr]);

		T0 = Fe0(X2, m_sBox);
		T1 = Fe3(X3, m_sBox);
		X0 ^= T0 + T1 + m_expKey[++keyCtr];
		X0 = (X0 >> 1) | (X0 << 31);
		X1 = (X1 << 1) | (X1 >> 31);
		X1 ^= (T0 + 2 * T1 + m_expKey[++keyCtr]);
	} 
	while (keyCtr != FNLRND);

	keyCtr = 4;
	X2 ^= m_expKey[keyCtr];
	X3 ^= m_expKey[++keyCtr];
	X0 ^= m_expKey[++keyCtr];
	X1 ^= m_expKey[++keyCtr];

	Utility::IntUtils::Le32ToBytes(X2, Output, OutOffset);
	Utility::IntUtils::Le32ToBytes(X3, Output, OutOffset + 4);
	Utility::IntUtils::Le32ToBytes(X0, Output, OutOffset + 8);
	Utility::IntUtils::Le32ToBytes(X1, Output, OutOffset + 12);
}

void THX::Encrypt512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if !defined(__AVX512__) && !defined(__AVX2__) && defined(__AVX__) && defined(CEX_COMPILER_MSC)
	THXEncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
#else
	Encrypt128(Input, InOffset, Output, OutOffset);
	Encrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt128(Input, InOffset + 48, Output, OutOffset + 48);
#endif
}

void THX::Encrypt1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if !defined(__AVX512__) && defined(__AVX2__) && defined(CEX_COMPILER_MSC)
	THXEncryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
#elif !defined(__AVX512__) && !defined(__AVX2__) && defined(__AVX__) && defined(CEX_COMPILER_MSC)
	THXEncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
	THXEncryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey, m_sBox);
#else
	Encrypt128(Input, InOffset, Output, OutOffset);
	Encrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt128(Input, InOffset + 48, Output, OutOffset + 48);
	Encrypt128(Input, InOffset + 64, Output, OutOffset + 64);
	Encrypt128(Input, InOffset + 80, Output, OutOffset + 80);
	Encrypt128(Input, InOffset + 96, Output, OutOffset + 96);
	Encrypt128(Input, InOffset + 112, Output, OutOffset + 112);
#endif
}

void THX::Encrypt2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(__AVX512__) && defined(CEX_COMPILER_MSC)
	THXEncryptW<Numeric::UInt512>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
#elif !defined(__AVX512__) && defined(__AVX2__) && defined(CEX_COMPILER_MSC)
	THXEncryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
	THXEncryptW<Numeric::UInt256>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey, m_sBox);
#elif !defined(__AVX512__) && !defined(__AVX2__) && defined(__AVX__) && defined(CEX_COMPILER_MSC)
	THXEncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey, m_sBox);
	THXEncryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey, m_sBox);
	THXEncryptW<Numeric::UInt128>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey, m_sBox);
	THXEncryptW<Numeric::UInt128>(Input, InOffset + 192, Output, OutOffset + 192, m_expKey, m_sBox);
#else
	Encrypt128(Input, InOffset, Output, OutOffset);
	Encrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt128(Input, InOffset + 48, Output, OutOffset + 48);
	Encrypt128(Input, InOffset + 64, Output, OutOffset + 64);
	Encrypt128(Input, InOffset + 80, Output, OutOffset + 80);
	Encrypt128(Input, InOffset + 96, Output, OutOffset + 96);
	Encrypt128(Input, InOffset + 112, Output, OutOffset + 112);
	Encrypt128(Input, InOffset + 128, Output, OutOffset + 128);
	Encrypt128(Input, InOffset + 144, Output, OutOffset + 144);
	Encrypt128(Input, InOffset + 160, Output, OutOffset + 160);
	Encrypt128(Input, InOffset + 176, Output, OutOffset + 176);
	Encrypt128(Input, InOffset + 192, Output, OutOffset + 192);
	Encrypt128(Input, InOffset + 208, Output, OutOffset + 208);
	Encrypt128(Input, InOffset + 224, Output, OutOffset + 224);
	Encrypt128(Input, InOffset + 240, Output, OutOffset + 240);
#endif
}

//~~~Helpers~~~//

void THX::LoadState(Digests ExtractorType)
{
	if (ExtractorType == Digests::None)
	{
		m_legalRounds.resize(2);
		m_legalRounds = { 16, 20 };

		m_legalKeySizes.resize(4);
		m_legalKeySizes[0] = SymmetricKeySize(16, 16, 0);
		m_legalKeySizes[1] = SymmetricKeySize(24, 16, 0);
		m_legalKeySizes[2] = SymmetricKeySize(32, 16, 0);
		m_legalKeySizes[3] = SymmetricKeySize(64, 16, 0);
	}
	else
	{
		m_legalRounds.resize(9);
		m_legalRounds = { 16, 18, 20, 22, 24, 26, 28, 30, 32 };

		// change: default at ideal size, a full block to key HMAC
		m_kdfKeySize = Helper::DigestFromName::GetBlockSize(m_kdfEngineType);
		// calculate max saturation of entropy when distribution code is used as key extension; subtract hash finalizer code + 1 byte HKDF counter
		m_kdfInfoMax = m_kdfKeySize - (Helper::DigestFromName::GetPaddingSize(m_kdfEngineType) + 1);
		m_legalKeySizes.resize(3);
		// min allowable HMAC key
		m_legalKeySizes[0] = SymmetricKeySize(Helper::DigestFromName::GetDigestSize(m_kdfEngineType), BLOCK_SIZE, m_kdfInfoMax);
		// best size, no ipad/opad zero-byte mix in HMAC
		m_legalKeySizes[1] = SymmetricKeySize(m_kdfKeySize, BLOCK_SIZE, m_kdfInfoMax);
		// triggers HKDF Extract
		m_legalKeySizes[2] = SymmetricKeySize(m_kdfKeySize * 2, BLOCK_SIZE, m_kdfInfoMax);
	}
}

uint THX::MdsEncode(uint K0, uint K1)
{
	uint B = ((K1 >> 24) & 0xff);
	uint G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	uint G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	uint temp = ((K1 << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);

	B = ((temp >> 24) & 0xff);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	temp = ((temp << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);
	B = ((temp >> 24) & 0xff);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	temp = ((temp << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);
	B = ((temp >> 24) & 0xff);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	temp = ((temp << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);
	temp ^= K0;
	B = ((temp >> 24) & 0xff);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	temp = ((temp << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);
	B = ((temp >> 24) & 0xff);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	temp = ((temp << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);
	B = ((temp >> 24) & 0xff);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	temp = ((temp << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);
	B = ((temp >> 24) & 0xff);
	G2 = ((B << 1) ^ ((B & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	G3 = ((B >> 1) ^ ((B & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ G2;
	temp = ((temp << 8) ^ (G3 << 24) ^ (G2 << 16) ^ (G3 << 8) ^ B);

	return temp;
}

uint THX::Mix4(const uint X, const std::vector<uint> &Key, const size_t Count)
{
	uint Y0 = (byte)X;
	uint Y1 = (byte)(X >> 8);
	uint Y2 = (byte)(X >> 16);
	uint Y3 = (byte)(X >> 24);

	// 512 key
	if (Count == 8)
	{
		Y0 = (byte)Q1[Y0] ^ (byte)Key[7];
		Y1 = (byte)Q0[Y1] ^ (byte)(Key[7] >> 8);
		Y2 = (byte)Q0[Y2] ^ (byte)(Key[7] >> 16);
		Y3 = (byte)Q1[Y3] ^ (byte)(Key[7] >> 24);

		Y0 = (byte)Q1[Y0] ^ (byte)Key[6];
		Y1 = (byte)Q1[Y1] ^ (byte)(Key[6] >> 8);
		Y2 = (byte)Q0[Y2] ^ (byte)(Key[6] >> 16);
		Y3 = (byte)Q0[Y3] ^ (byte)(Key[6] >> 24);

		Y0 = (byte)Q0[Y0] ^ (byte)Key[5];
		Y1 = (byte)Q1[Y1] ^ (byte)(Key[5] >> 8);
		Y2 = (byte)Q1[Y2] ^ (byte)(Key[5] >> 16);
		Y3 = (byte)Q0[Y3] ^ (byte)(Key[5] >> 24);

		Y0 = (byte)Q0[Y0] ^ (byte)Key[4];
		Y1 = (byte)Q0[Y1] ^ (byte)(Key[4] >> 8);
		Y2 = (byte)Q1[Y2] ^ (byte)(Key[4] >> 16);
		Y3 = (byte)Q1[Y3] ^ (byte)(Key[4] >> 24);
	}
	// 256 bit key
	if (Count > 3)
	{
		Y0 = (byte)Q1[Y0] ^ (byte)Key[3];
		Y1 = (byte)Q0[Y1] ^ (byte)(Key[3] >> 8);
		Y2 = (byte)Q0[Y2] ^ (byte)(Key[3] >> 16);
		Y3 = (byte)Q1[Y3] ^ (byte)(Key[3] >> 24);
	}
	// 192 bit key
	if (Count > 2)
	{
		Y0 = (byte)Q1[Y0] ^ (byte)Key[2];
		Y1 = (byte)Q1[Y1] ^ (byte)(Key[2] >> 8);
		Y2 = (byte)Q0[Y2] ^ (byte)(Key[2] >> 16);
		Y3 = (byte)Q0[Y3] ^ (byte)(Key[2] >> 24);
	}

	// return the MDS matrix multiply
	return M0[(byte)Q0[(byte)Q0[Y0] ^ (byte)Key[1]] ^ (byte)Key[0]] ^
		M1[(byte)Q0[(byte)Q1[Y1] ^ (byte)(Key[1] >> 8)] ^ (byte)(Key[0] >> 8)] ^
		M2[(byte)Q1[(byte)Q0[Y2] ^ (byte)(Key[1] >> 16)] ^ (byte)(Key[0] >> 16)] ^
		M3[(byte)Q1[(byte)Q1[Y3] ^ (byte)(Key[1] >> 24)] ^ (byte)(Key[0] >> 24)];
}

void THX::Mix16(const uint X, const std::vector<byte> &Key, const size_t Count, std::vector<uint> &Output)
{
	uint Y0, Y1, Y2, Y3;
	Y0 = Y1 = Y2 = Y3 = X;

	if (Count == 64)
	{
		Y0 = (byte)(Q1[Y0] ^ Key[28]);
		Y1 = (byte)(Q0[Y1] ^ Key[29]);
		Y2 = (byte)(Q0[Y2] ^ Key[30]);
		Y3 = (byte)(Q1[Y3] ^ Key[31]);

		Y0 = (byte)(Q1[Y0] ^ Key[24]);
		Y1 = (byte)(Q1[Y1] ^ Key[25]);
		Y2 = (byte)(Q0[Y2] ^ Key[26]);
		Y3 = (byte)(Q0[Y3] ^ Key[27]);

		Y0 = (byte)(Q0[Y0] ^ Key[20]);
		Y1 = (byte)(Q1[Y1] ^ Key[21]);
		Y2 = (byte)(Q1[Y2] ^ Key[22]);
		Y3 = (byte)(Q0[Y3] ^ Key[23]);

		Y0 = (byte)(Q0[Y0] ^ Key[16]);
		Y1 = (byte)(Q0[Y1] ^ Key[17]);
		Y2 = (byte)(Q1[Y2] ^ Key[18]);
		Y3 = (byte)(Q1[Y3] ^ Key[19]);
	}
	if (Count > 24)
	{
		Y0 = (byte)(Q1[Y0] ^ Key[12]);
		Y1 = (byte)(Q0[Y1] ^ Key[13]);
		Y2 = (byte)(Q0[Y2] ^ Key[14]);
		Y3 = (byte)(Q1[Y3] ^ Key[15]);
	}
	if (Count > 16)
	{
		Y0 = (byte)(Q1[Y0] ^ Key[8]);
		Y1 = (byte)(Q1[Y1] ^ Key[9]);
		Y2 = (byte)(Q0[Y2] ^ Key[10]);
		Y3 = (byte)(Q0[Y3] ^ Key[11]);
	}

	std::vector<uint> tmp {
		M0[Q0[Q0[Y0] ^ Key[4]] ^ Key[0]],
		M1[Q0[Q1[Y1] ^ Key[5]] ^ Key[1]],
		M2[Q1[Q0[Y2] ^ Key[6]] ^ Key[2]],
		M3[Q1[Q1[Y3] ^ Key[7]] ^ Key[3]]
	};

	Output = tmp;
}

CEX_OPTIMIZE_IGNORE
void THX::Prefetch()
{
	// timing defence: pre-load tables into cache
#if defined(__AVX__)
	PREFETCHT0(&m_sBox[0], m_sBox.size() * sizeof(uint));
	PREFETCHT0(&M0[0], 256 * sizeof(uint));
	PREFETCHT0(&M1[0], 256 * sizeof(uint));
	PREFETCHT0(&M2[0], 256 * sizeof(uint));
	PREFETCHT0(&M3[0], 256 * sizeof(uint));
	PREFETCHT0(&Q0[0], 256 * sizeof(uint));
	PREFETCHT0(&Q1[0], 256 * sizeof(uint));
#else
	volatile uint dummy;
	for (size_t i = 0; i < m_sBox.size(); ++i)
		dummy ^= m_sBox[i];
	for (size_t i = 0; i < 256; ++i)
		dummy ^= M0[i];
	for (size_t i = 0; i < 256; ++i)
		dummy ^= M1[i];
	for (size_t i = 0; i < 256; ++i)
		dummy ^= M2[i];
	for (size_t i = 0; i < 256; ++i)
		dummy ^= M3[i];
	for (size_t i = 0; i < 256; ++i)
		dummy ^= Q0[i];
	for (size_t i = 0; i < 256; ++i)
		dummy ^= Q1[i];

#endif

}
CEX_OPTIMIZE_RESUME

NAMESPACE_BLOCKEND