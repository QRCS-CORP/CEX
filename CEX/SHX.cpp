#include "SHX.h"
#include "Serpent.h"
#include "DigestFromName.h"
#include "HKDF.h"
#include "IntUtils.h"
#include "MemUtils.h"
#if defined(__AVX512__)
#	include "UInt512.h"
#elif defined(__AVX2__)
#	include "UInt256.h"
#elif defined(__AVX__)
#	include "UInt128.h"
#endif


NAMESPACE_BLOCK

const std::string SHX::CLASS_NAME("SHX");
const std::string SHX::DEF_DSTINFO("SHX version 1 information string");

//~~~Properties~~~//

const size_t SHX::BlockSize()
{
	return BLOCK_SIZE;
}

std::vector<byte> &SHX::DistributionCode()
{
	return m_kdfInfo;
}

const size_t SHX::DistributionCodeMax()
{
	return m_kdfInfoMax;
}

const BlockCiphers SHX::Enumeral()
{
	return (m_kdfEngineType == Digests::None) ? BlockCiphers::Serpent : BlockCiphers::SHX;
}

const bool SHX::IsEncryption()
{
	return m_isEncryption;
}

const bool SHX::IsInitialized()
{
	return m_isInitialized;
}

const Digests SHX::KdfEngine()
{
	return m_kdfEngineType;
}

const std::vector<SymmetricKeySize> &SHX::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::vector<size_t> &SHX::LegalRounds()
{
	return m_legalRounds;
}

const std::string &SHX::Name()
{
	return CLASS_NAME;
}

const size_t SHX::Rounds()
{
	return m_rndCount;
}

const size_t SHX::StateCacheSize()
{
	return STATE_PRECACHED;
}

//~~~Constructor~~~//

SHX::SHX(Digests KdfEngineType, size_t Rounds)
	:
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_kdfEngine(KdfEngineType == Digests::None ? 0 : Helper::DigestFromName::GetInstance(KdfEngineType)),
	m_kdfEngineType(KdfEngineType),
	m_kdfInfo(DEF_DSTINFO.begin(), DEF_DSTINFO.end()),
	m_kdfInfoMax(0),
	m_kdfKeySize(0),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_legalRounds(0),
	m_rndCount(Rounds)
{
	if (KdfEngineType != Digests::None && Rounds != 32 && Rounds != 40 && Rounds != 48 && Rounds != 56 && Rounds != 64)
			throw CryptoSymmetricCipherException("SHX:CTor", "Invalid rounds size! Sizes supported are 32, 40, 48, 56, 64.");

	LoadState(KdfEngineType);
}

SHX::SHX(IDigest *KdfEngine, size_t Rounds)
	:
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_kdfEngine(KdfEngine),
	m_kdfEngineType(m_kdfEngine != 0 ? KdfEngine->Enumeral() : Digests::None),
	m_kdfInfo(DEF_DSTINFO.begin(), DEF_DSTINFO.end()),
	m_kdfInfoMax(0),
	m_kdfKeySize(0),
	m_isEncryption(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_legalRounds(0),
	m_rndCount(Rounds)
{
	if (Rounds != 32 && Rounds != 40 && Rounds != 48 && Rounds != 56 && Rounds != 64)
		throw CryptoSymmetricCipherException("SHX:CTor", "Invalid rounds size! Sizes supported are 32, 40, 48, 56, 64.");

	LoadState(KdfEngine->Enumeral());
}

SHX::~SHX()
{
	Destroy();
}

//~~~Public Functions~~~//

void SHX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt128(Input, 0, Output, 0);
}

void SHX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt128(Input, InOffset, Output, OutOffset);
}

void SHX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt128(Input, 0, Output, 0);
}

void SHX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt128(Input, InOffset, Output, OutOffset);
}

void SHX::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_kdfEngineType = Digests::None;
		m_kdfInfoMax = 0;
		m_kdfKeySize = 0;
		m_isDestroyed = false;
		m_isEncryption = false;
		m_isInitialized = false;
		m_rndCount = 0;

		try
		{
			Utility::IntUtils::ClearVector(m_expKey);
			Utility::IntUtils::ClearVector(m_kdfInfo);
			Utility::IntUtils::ClearVector(m_legalKeySizes);
			Utility::IntUtils::ClearVector(m_legalRounds);

			if (m_kdfEngine != 0 && m_destroyEngine)
				delete m_kdfEngine;

			m_destroyEngine = false;
		}
		catch (std::exception& ex)
		{
			throw CryptoSymmetricCipherException("SHX:Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

void SHX::Initialize(bool Encryption, ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(m_legalKeySizes, KeyParams.Key().size()))
		throw CryptoSymmetricCipherException("SHX:Initialize", "Invalid key size! Key must be one of the LegalKeySizes() in length.");
	if (m_kdfEngineType != Enumeration::Digests::None && KeyParams.Info().size() > m_kdfInfoMax)
		throw CryptoSymmetricCipherException("SHX:Initialize", "Invalid info size! Info parameter must be no longer than DistributionCodeMax size.");

	if (KeyParams.Info().size() > 0)
		m_kdfInfo = KeyParams.Info();

	m_isEncryption = Encryption;
	// expand the key
	ExpandKey(KeyParams.Key());
	// ready to transform data
	m_isInitialized = true;
}

void SHX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (m_isEncryption)
		Encrypt128(Input, 0, Output, 0);
	else
		Decrypt128(Input, 0, Output, 0);
}

void SHX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt128(Input, InOffset, Output, OutOffset);
	else
		Decrypt128(Input, InOffset, Output, OutOffset);
}

void SHX::Transform512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt512(Input, InOffset, Output, OutOffset);
	else
		Decrypt512(Input, InOffset, Output, OutOffset);
}

void SHX::Transform1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt1024(Input, InOffset, Output, OutOffset);
	else
		Decrypt1024(Input, InOffset, Output, OutOffset);
}

void SHX::Transform2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt2048(Input, InOffset, Output, OutOffset);
	else
		Decrypt2048(Input, InOffset, Output, OutOffset);
}

//~~~Key Schedule~~~//

void SHX::ExpandKey(const std::vector<byte> &Key)
{
	if (m_kdfEngineType != Enumeration::Digests::None)
	{
		// hkdf key expansion
		SecureExpand(Key);
	}
	else
	{
		// standard serpent key expansion + k512
		StandardExpand(Key);
	}
}

void SHX::SecureExpand(const std::vector<byte> &Key)
{
	// expanded key size
	size_t keySize = 4 * (m_rndCount + 1);
	size_t keyBytes = keySize * 4;

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
	for (size_t i = 0; i < m_expKey.size(); ++i)
		m_expKey[i] = Utility::IntUtils::LeBytesTo32(rawKey, i * sizeof(uint));
}

void SHX::StandardExpand(const std::vector<byte> &Key)
{
	uint cnt = 0;
	uint index = 0;
	size_t padSize = Key.size() < 32 ? 16 : Key.size() / 2;
	std::vector<uint> Wp(padSize, 0);
	size_t offset = 0;

	// CHANGE: 512 key gets 8 extra rounds
	m_rndCount = (Key.size() == 64) ? 40 : 32;
	size_t keySize = 4 * (m_rndCount + 1);

	// step 1: reverse copy key to temp array
	for (offset = Key.size(); offset > 0; offset -= 4)
		Wp[index++] = Utility::IntUtils::BeBytesTo32(Key, offset - 4);

	// pad small key
	if (index < 8)
		Wp[index] = 1;

	// initialize the key
	std::vector<uint> Wk(keySize, 0);

	if (padSize == 16)
	{
		// 32 byte key
		// step 2: rotate k into w(k) ints
		for (size_t i = 8; i < 16; i++)
			Wp[i] = Utility::IntUtils::RotL32((uint)(Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 8)), 11);

		// copy to expanded key
		Utility::MemUtils::Copy<uint>(Wp, 8, Wk, 0, 8 * sizeof(uint));

		// step 3: calculate remainder of rounds with rotating polynomial
		for (size_t i = 8; i < keySize; i++)
			Wk[i] = Utility::IntUtils::RotL32((uint)(Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
	}
	else
	{
		// *extended*: 64 byte key
		// step 3: rotate k into w(k) ints, with extended polynominal
		// Wp := (Wp-16 ^ Wp-13 ^ Wp-11 ^ Wp-10 ^ Wp-8 ^ Wp-5 ^ Wp-3 ^ Wp-1 ^ PHI ^ i) <<< 11
		for (size_t i = 16; i < 32; i++)
			Wp[i] = Utility::IntUtils::RotL32((uint)(Wp[i - 16] ^ Wp[i - 13] ^ Wp[i - 11] ^ Wp[i - 10] ^ Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 16)), 11);

		// copy to expanded key
		Utility::MemUtils::Copy<uint>(Wp, 16, Wk, 0, 16 * sizeof(uint));

		// step 3: calculate remainder of rounds with rotating polynomial
		for (size_t i = 16; i < keySize; i++)
			Wk[i] = Utility::IntUtils::RotL32((uint)(Wk[i - 16] ^ Wk[i - 13] ^ Wk[i - 11] ^ Wk[i - 10] ^ Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
	}

	// step 4: create the working keys by processing with the Sbox and IP
	while (cnt < keySize - 4)
	{
		Sb3(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb2(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb1(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb0(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb7(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb6(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb5(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
		Sb4(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]); cnt += 4;
	}

	// last round
	Sb3(Wk[cnt], Wk[cnt + 1], Wk[cnt + 2], Wk[cnt + 3]);

	m_expKey = Wk;
}

//~~~Rounds Processing~~~//

void SHX::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t FNLRND = 4;
	size_t keyCtr = m_expKey.size();

	// input round
	uint R3 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 12);
	uint R2 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 8);
	uint R1 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 4);
	uint R0 = Utility::IntUtils::LeBytesTo32(Input, InOffset);

	R3 ^= m_expKey[--keyCtr];
	R2 ^= m_expKey[--keyCtr];
	R1 ^= m_expKey[--keyCtr];
	R0 ^= m_expKey[--keyCtr];

	// process 8 round blocks
	do
	{
		Ib7(R0, R1, R2, R3);
		R3 ^= m_expKey[--keyCtr];
		R2 ^= m_expKey[--keyCtr];
		R1 ^= m_expKey[--keyCtr];
		R0 ^= m_expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib6(R0, R1, R2, R3);
		R3 ^= m_expKey[--keyCtr];
		R2 ^= m_expKey[--keyCtr];
		R1 ^= m_expKey[--keyCtr];
		R0 ^= m_expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib5(R0, R1, R2, R3);
		R3 ^= m_expKey[--keyCtr];
		R2 ^= m_expKey[--keyCtr];
		R1 ^= m_expKey[--keyCtr];
		R0 ^= m_expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib4(R0, R1, R2, R3);
		R3 ^= m_expKey[--keyCtr];
		R2 ^= m_expKey[--keyCtr];
		R1 ^= m_expKey[--keyCtr];
		R0 ^= m_expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib3(R0, R1, R2, R3);
		R3 ^= m_expKey[--keyCtr];
		R2 ^= m_expKey[--keyCtr];
		R1 ^= m_expKey[--keyCtr];
		R0 ^= m_expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib2(R0, R1, R2, R3);
		R3 ^= m_expKey[--keyCtr];
		R2 ^= m_expKey[--keyCtr];
		R1 ^= m_expKey[--keyCtr];
		R0 ^= m_expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib1(R0, R1, R2, R3);
		R3 ^= m_expKey[--keyCtr];
		R2 ^= m_expKey[--keyCtr];
		R1 ^= m_expKey[--keyCtr];
		R0 ^= m_expKey[--keyCtr];
		InverseTransform(R0, R1, R2, R3);

		Ib0(R0, R1, R2, R3);

		// skip on last block
		if (keyCtr != FNLRND)
		{
			R3 ^= m_expKey[--keyCtr];
			R2 ^= m_expKey[--keyCtr];
			R1 ^= m_expKey[--keyCtr];
			R0 ^= m_expKey[--keyCtr];
			InverseTransform(R0, R1, R2, R3);
		}
	} 
	while (keyCtr != FNLRND);

	// last round
	Utility::IntUtils::Le32ToBytes(R3 ^ m_expKey[--keyCtr], Output, OutOffset + 12);
	Utility::IntUtils::Le32ToBytes(R2 ^ m_expKey[--keyCtr], Output, OutOffset + 8);
	Utility::IntUtils::Le32ToBytes(R1 ^ m_expKey[--keyCtr], Output, OutOffset + 4);
	Utility::IntUtils::Le32ToBytes(R0 ^ m_expKey[--keyCtr], Output, OutOffset);
}

void SHX::Decrypt512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if !defined(__AVX512__) && !defined(__AVX2__) && defined(__AVX__)
	DecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey);
#else
	Decrypt128(Input, InOffset, Output, OutOffset);
	Decrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt128(Input, InOffset + 48, Output, OutOffset + 48);
#endif
}

void SHX::Decrypt1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if !defined(__AVX512__) && defined(__AVX2__)
	DecryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey);
#elif !defined(__AVX512__) && !defined(__AVX2__) && defined(__AVX__)
	DecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey);
	DecryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey);
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

void SHX::Decrypt2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(__AVX512__)
	DecryptW<Numeric::UInt512>(Input, InOffset, Output, OutOffset, m_expKey);
#elif !defined(__AVX512__) && defined(__AVX2__)
	DecryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey);
	DecryptW<Numeric::UInt256>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey);
#elif !defined(__AVX512__) && !defined(__AVX2__) && defined(__AVX__)
	DecryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey);
	DecryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey);
	DecryptW<Numeric::UInt128>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey);
	DecryptW<Numeric::UInt128>(Input, InOffset + 192, Output, OutOffset + 192, m_expKey);
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

void SHX::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t FNLRND = m_expKey.size() - 5;
	int keyCtr = -1;

	// input round
	uint R0 = Utility::IntUtils::LeBytesTo32(Input, InOffset);
	uint R1 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 4);
	uint R2 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 8);
	uint R3 = Utility::IntUtils::LeBytesTo32(Input, InOffset + 12);

	// process 8 round blocks
	do
	{
		R0 ^= m_expKey[++keyCtr];
		R1 ^= m_expKey[++keyCtr];
		R2 ^= m_expKey[++keyCtr];
		R3 ^= m_expKey[++keyCtr];
		Sb0(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[++keyCtr];
		R1 ^= m_expKey[++keyCtr];
		R2 ^= m_expKey[++keyCtr];
		R3 ^= m_expKey[++keyCtr];
		Sb1(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[++keyCtr];
		R1 ^= m_expKey[++keyCtr];
		R2 ^= m_expKey[++keyCtr];
		R3 ^= m_expKey[++keyCtr];
		Sb2(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[++keyCtr];
		R1 ^= m_expKey[++keyCtr];
		R2 ^= m_expKey[++keyCtr];
		R3 ^= m_expKey[++keyCtr];
		Sb3(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[++keyCtr];
		R1 ^= m_expKey[++keyCtr];
		R2 ^= m_expKey[++keyCtr];
		R3 ^= m_expKey[++keyCtr];
		Sb4(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[++keyCtr];
		R1 ^= m_expKey[++keyCtr];
		R2 ^= m_expKey[++keyCtr];
		R3 ^= m_expKey[++keyCtr];
		Sb5(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[++keyCtr];
		R1 ^= m_expKey[++keyCtr];
		R2 ^= m_expKey[++keyCtr];
		R3 ^= m_expKey[++keyCtr];
		Sb6(R0, R1, R2, R3);
		LinearTransform(R0, R1, R2, R3);

		R0 ^= m_expKey[++keyCtr];
		R1 ^= m_expKey[++keyCtr];
		R2 ^= m_expKey[++keyCtr];
		R3 ^= m_expKey[++keyCtr];
		Sb7(R0, R1, R2, R3);

		// skip on last block
		if (keyCtr != FNLRND)
			LinearTransform(R0, R1, R2, R3);
	} 
	while (keyCtr != FNLRND);

	// last round
	Utility::IntUtils::Le32ToBytes(m_expKey[++keyCtr] ^ R0, Output, OutOffset);
	Utility::IntUtils::Le32ToBytes(m_expKey[++keyCtr] ^ R1, Output, OutOffset + 4);
	Utility::IntUtils::Le32ToBytes(m_expKey[++keyCtr] ^ R2, Output, OutOffset + 8);
	Utility::IntUtils::Le32ToBytes(m_expKey[++keyCtr] ^ R3, Output, OutOffset + 12);
}

void SHX::Encrypt512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if !defined(__AVX512__) && !defined(__AVX2__) && defined(__AVX__)
	EncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey);
#else
	Encrypt128(Input, InOffset, Output, OutOffset);
	Encrypt128(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt128(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt128(Input, InOffset + 48, Output, OutOffset + 48);
#endif
}

void SHX::Encrypt1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if !defined(__AVX512__) && defined(__AVX2__)
	EncryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey);
#elif !defined(__AVX512__) && !defined(__AVX2__) && defined(__AVX__)
	EncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey);
	EncryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey);
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

void SHX::Encrypt2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(__AVX512__)
	EncryptW<Numeric::UInt512>(Input, InOffset, Output, OutOffset, m_expKey);
#elif !defined(__AVX512__) && defined(__AVX2__)
	EncryptW<Numeric::UInt256>(Input, InOffset, Output, OutOffset, m_expKey);
	EncryptW<Numeric::UInt256>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey);
#elif !defined(__AVX512__) && !defined(__AVX2__) && defined(__AVX__)
	EncryptW<Numeric::UInt128>(Input, InOffset, Output, OutOffset, m_expKey);
	EncryptW<Numeric::UInt128>(Input, InOffset + 64, Output, OutOffset + 64, m_expKey);
	EncryptW<Numeric::UInt128>(Input, InOffset + 128, Output, OutOffset + 128, m_expKey);
	EncryptW<Numeric::UInt128>(Input, InOffset + 192, Output, OutOffset + 192, m_expKey);
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

//~~~Helper Functions~~~//

void SHX::LoadState(Digests ExtractorType)
{
	if (ExtractorType == Digests::None)
	{
		m_legalRounds.resize(2);
		m_legalRounds = { 32, 40 };

		m_legalKeySizes.resize(4);
		m_legalKeySizes[0] = SymmetricKeySize(16, 16, 0);
		m_legalKeySizes[1] = SymmetricKeySize(24, 16, 0);
		m_legalKeySizes[2] = SymmetricKeySize(32, 16, 0);
		m_legalKeySizes[3] = SymmetricKeySize(64, 16, 0);
	}
	else
	{
		m_legalRounds.resize(5);
		m_legalRounds = { 32, 40, 48, 56, 64 };

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

NAMESPACE_BLOCKEND