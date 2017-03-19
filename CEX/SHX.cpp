#include "SHX.h"
#include "Serpent.h"
#include "ArrayUtils.h"
#include "DigestFromName.h"
#include "HKDF.h"
#include "IntUtils.h"
#include "UInt128.h"
#include "UInt256.h"

NAMESPACE_BLOCK

using Helper::DigestFromName;
using Utility::IntUtils;
using Numeric::UInt128;
using Numeric::UInt256;

const std::string SHX::DEF_INFO = "SHX version 1 information string";

//~~~Constructor~~~//

SHX::SHX(Digests KdfEngineType, size_t Rounds)
	:
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_kdfEngine(KdfEngineType == Digests::None ? 0 : DigestFromName::GetInstance(KdfEngineType)),
	m_kdfEngineType(KdfEngineType),
	m_kdfInfo(DEF_INFO.begin(), DEF_INFO.end()),
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
	m_kdfInfo(DEF_INFO.begin(), DEF_INFO.end()),
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
	Decrypt16(Input, 0, Output, 0);
}

void SHX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt16(Input, InOffset, Output, OutOffset);
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
			Utility::ArrayUtils::ClearVector(m_expKey);
			Utility::ArrayUtils::ClearVector(m_kdfInfo);
			Utility::ArrayUtils::ClearVector(m_legalKeySizes);
			Utility::ArrayUtils::ClearVector(m_legalRounds);

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

void SHX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt16(Input, 0, Output, 0);
}

void SHX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt16(Input, InOffset, Output, OutOffset);
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
		Encrypt16(Input, 0, Output, 0);
	else
		Decrypt16(Input, 0, Output, 0);
}

void SHX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt16(Input, InOffset, Output, OutOffset);
	else
		Decrypt16(Input, InOffset, Output, OutOffset);
}

void SHX::Transform64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt64(Input, InOffset, Output, OutOffset);
	else
		Decrypt64(Input, InOffset, Output, OutOffset);
}

void SHX::Transform128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt128(Input, InOffset, Output, OutOffset);
	else
		Decrypt128(Input, InOffset, Output, OutOffset);
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
		memcpy(&kdfKey[0], &Key[0], m_kdfKeySize);
		size_t saltSize = Key.size() - m_kdfKeySize;
		std::vector<byte> kdfSalt(saltSize, 0);
		memcpy(&kdfSalt[0], &Key[m_kdfKeySize], saltSize);
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
	memcpy(&m_expKey[0], &rawKey[0], keyBytes);
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
		Wp[index++] = IntUtils::BytesToBe32(Key, offset - 4);

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
			Wp[i] = IntUtils::RotL32((uint)(Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 8)), 11);

		// copy to expanded key
		memcpy(&Wk[0], &Wp[8], 8 * sizeof(uint));

		// step 3: calculate remainder of rounds with rotating polynomial
		for (size_t i = 8; i < keySize; i++)
			Wk[i] = IntUtils::RotL32((uint)(Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
	}
	else
	{
		// *extended*: 64 byte key
		// step 3: rotate k into w(k) ints, with extended polynominal
		// Wp := (Wp-16 ^ Wp-13 ^ Wp-11 ^ Wp-10 ^ Wp-8 ^ Wp-5 ^ Wp-3 ^ Wp-1 ^ PHI ^ i) <<< 11
		for (size_t i = 16; i < 32; i++)
			Wp[i] = IntUtils::RotL32((uint)(Wp[i - 16] ^ Wp[i - 13] ^ Wp[i - 11] ^ Wp[i - 10] ^ Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 16)), 11);

		// copy to expanded key
		memcpy(&Wk[0], &Wp[16], 16 * sizeof(uint));

		// step 3: calculate remainder of rounds with rotating polynomial
		for (size_t i = 16; i < keySize; i++)
			Wk[i] = IntUtils::RotL32((uint)(Wk[i - 16] ^ Wk[i - 13] ^ Wk[i - 11] ^ Wk[i - 10] ^ Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
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

void SHX::Decrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = 4;
	size_t keyCtr = m_expKey.size();

	// input round
	uint R3 = IntUtils::BytesToLe32(Input, InOffset + 12);
	uint R2 = IntUtils::BytesToLe32(Input, InOffset + 8);
	uint R1 = IntUtils::BytesToLe32(Input, InOffset + 4);
	uint R0 = IntUtils::BytesToLe32(Input, InOffset);

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
		if (keyCtr != LRD)
		{
			R3 ^= m_expKey[--keyCtr];
			R2 ^= m_expKey[--keyCtr];
			R1 ^= m_expKey[--keyCtr];
			R0 ^= m_expKey[--keyCtr];
			InverseTransform(R0, R1, R2, R3);
		}
	} 
	while (keyCtr != LRD);

	// last round
	IntUtils::Le32ToBytes(R3 ^ m_expKey[--keyCtr], Output, OutOffset + 12);
	IntUtils::Le32ToBytes(R2 ^ m_expKey[--keyCtr], Output, OutOffset + 8);
	IntUtils::Le32ToBytes(R1 ^ m_expKey[--keyCtr], Output, OutOffset + 4);
	IntUtils::Le32ToBytes(R0 ^ m_expKey[--keyCtr], Output, OutOffset);
}

void SHX::Decrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = 4;
	size_t keyCtr = m_expKey.size();

	// input round
	UInt128 R0(Input, InOffset);
	UInt128 R1(Input, InOffset + 16);
	UInt128 R2(Input, InOffset + 32);
	UInt128 R3(Input, InOffset + 48);
	UInt128::Transpose(R0, R1, R2, R3);

	R3 ^= UInt128(m_expKey[--keyCtr]);
	R2 ^= UInt128(m_expKey[--keyCtr]);
	R1 ^= UInt128(m_expKey[--keyCtr]);
	R0 ^= UInt128(m_expKey[--keyCtr]);

	// process 8 round blocks
	do
	{
		Ib7(R0, R1, R2, R3);
		R3 ^= UInt128(m_expKey[--keyCtr]);
		R2 ^= UInt128(m_expKey[--keyCtr]);
		R1 ^= UInt128(m_expKey[--keyCtr]);
		R0 ^= UInt128(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib6(R0, R1, R2, R3);
		R3 ^= UInt128(m_expKey[--keyCtr]);
		R2 ^= UInt128(m_expKey[--keyCtr]);
		R1 ^= UInt128(m_expKey[--keyCtr]);
		R0 ^= UInt128(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib5(R0, R1, R2, R3);
		R3 ^= UInt128(m_expKey[--keyCtr]);
		R2 ^= UInt128(m_expKey[--keyCtr]);
		R1 ^= UInt128(m_expKey[--keyCtr]);
		R0 ^= UInt128(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib4(R0, R1, R2, R3);
		R3 ^= UInt128(m_expKey[--keyCtr]);
		R2 ^= UInt128(m_expKey[--keyCtr]);
		R1 ^= UInt128(m_expKey[--keyCtr]);
		R0 ^= UInt128(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib3(R0, R1, R2, R3);
		R3 ^= UInt128(m_expKey[--keyCtr]);
		R2 ^= UInt128(m_expKey[--keyCtr]);
		R1 ^= UInt128(m_expKey[--keyCtr]);
		R0 ^= UInt128(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib2(R0, R1, R2, R3);
		R3 ^= UInt128(m_expKey[--keyCtr]);
		R2 ^= UInt128(m_expKey[--keyCtr]);
		R1 ^= UInt128(m_expKey[--keyCtr]);
		R0 ^= UInt128(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib1(R0, R1, R2, R3);
		R3 ^= UInt128(m_expKey[--keyCtr]);
		R2 ^= UInt128(m_expKey[--keyCtr]);
		R1 ^= UInt128(m_expKey[--keyCtr]);
		R0 ^= UInt128(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib0(R0, R1, R2, R3);

		// skip on last block
		if (keyCtr != LRD)
		{
			R3 ^= UInt128(m_expKey[--keyCtr]);
			R2 ^= UInt128(m_expKey[--keyCtr]);
			R1 ^= UInt128(m_expKey[--keyCtr]);
			R0 ^= UInt128(m_expKey[--keyCtr]);
			InverseTransform64(R0, R1, R2, R3);
		}
	} 
	while (keyCtr != LRD);

	// last round
	R3 ^= UInt128(m_expKey[--keyCtr]);
	R2 ^= UInt128(m_expKey[--keyCtr]);
	R1 ^= UInt128(m_expKey[--keyCtr]);
	R0 ^= UInt128(m_expKey[--keyCtr]);

	UInt128::Transpose(R0, R1, R2, R3);
	R0.StoreLE(Output, OutOffset);
	R1.StoreLE(Output, OutOffset + 16);
	R2.StoreLE(Output, OutOffset + 32);
	R3.StoreLE(Output, OutOffset + 48);
}

void SHX::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = 4;
	size_t keyCtr = m_expKey.size();

	// input round
	UInt256 R0(Input, InOffset);
	UInt256 R1(Input, InOffset + 32);
	UInt256 R2(Input, InOffset + 64);
	UInt256 R3(Input, InOffset + 96);
	UInt256::Transpose(R0, R1, R2, R3);

	R3 ^= UInt256(m_expKey[--keyCtr]);
	R2 ^= UInt256(m_expKey[--keyCtr]);
	R1 ^= UInt256(m_expKey[--keyCtr]);
	R0 ^= UInt256(m_expKey[--keyCtr]);

	// process 8 round blocks
	do
	{
		Ib7(R0, R1, R2, R3);
		R3 ^= UInt256(m_expKey[--keyCtr]);
		R2 ^= UInt256(m_expKey[--keyCtr]);
		R1 ^= UInt256(m_expKey[--keyCtr]);
		R0 ^= UInt256(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib6(R0, R1, R2, R3);
		R3 ^= UInt256(m_expKey[--keyCtr]);
		R2 ^= UInt256(m_expKey[--keyCtr]);
		R1 ^= UInt256(m_expKey[--keyCtr]);
		R0 ^= UInt256(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib5(R0, R1, R2, R3);
		R3 ^= UInt256(m_expKey[--keyCtr]);
		R2 ^= UInt256(m_expKey[--keyCtr]);
		R1 ^= UInt256(m_expKey[--keyCtr]);
		R0 ^= UInt256(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib4(R0, R1, R2, R3);
		R3 ^= UInt256(m_expKey[--keyCtr]);
		R2 ^= UInt256(m_expKey[--keyCtr]);
		R1 ^= UInt256(m_expKey[--keyCtr]);
		R0 ^= UInt256(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib3(R0, R1, R2, R3);
		R3 ^= UInt256(m_expKey[--keyCtr]);
		R2 ^= UInt256(m_expKey[--keyCtr]);
		R1 ^= UInt256(m_expKey[--keyCtr]);
		R0 ^= UInt256(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib2(R0, R1, R2, R3);
		R3 ^= UInt256(m_expKey[--keyCtr]);
		R2 ^= UInt256(m_expKey[--keyCtr]);
		R1 ^= UInt256(m_expKey[--keyCtr]);
		R0 ^= UInt256(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib1(R0, R1, R2, R3);
		R3 ^= UInt256(m_expKey[--keyCtr]);
		R2 ^= UInt256(m_expKey[--keyCtr]);
		R1 ^= UInt256(m_expKey[--keyCtr]);
		R0 ^= UInt256(m_expKey[--keyCtr]);
		InverseTransform64(R0, R1, R2, R3);

		Ib0(R0, R1, R2, R3);

		// skip on last block
		if (keyCtr != LRD)
		{
			R3 ^= UInt256(m_expKey[--keyCtr]);
			R2 ^= UInt256(m_expKey[--keyCtr]);
			R1 ^= UInt256(m_expKey[--keyCtr]);
			R0 ^= UInt256(m_expKey[--keyCtr]);
			InverseTransform64(R0, R1, R2, R3);
		}
	} while (keyCtr != LRD);

	// last round
	R3 ^= UInt256(m_expKey[--keyCtr]);
	R2 ^= UInt256(m_expKey[--keyCtr]);
	R1 ^= UInt256(m_expKey[--keyCtr]);
	R0 ^= UInt256(m_expKey[--keyCtr]);

	UInt256::Transpose(R0, R1, R2, R3);
	R0.StoreLE(Output, OutOffset);
	R1.StoreLE(Output, OutOffset + 32);
	R2.StoreLE(Output, OutOffset + 64);
	R3.StoreLE(Output, OutOffset + 96);
}

void SHX::Encrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = m_expKey.size() - 5;
	int keyCtr = -1;

	// input round
	uint R0 = IntUtils::BytesToLe32(Input, InOffset);
	uint R1 = IntUtils::BytesToLe32(Input, InOffset + 4);
	uint R2 = IntUtils::BytesToLe32(Input, InOffset + 8);
	uint R3 = IntUtils::BytesToLe32(Input, InOffset + 12);

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
		if (keyCtr != LRD)
			LinearTransform(R0, R1, R2, R3);
	} 
	while (keyCtr != LRD);

	// last round
	IntUtils::Le32ToBytes(m_expKey[++keyCtr] ^ R0, Output, OutOffset);
	IntUtils::Le32ToBytes(m_expKey[++keyCtr] ^ R1, Output, OutOffset + 4);
	IntUtils::Le32ToBytes(m_expKey[++keyCtr] ^ R2, Output, OutOffset + 8);
	IntUtils::Le32ToBytes(m_expKey[++keyCtr] ^ R3, Output, OutOffset + 12);
}

void SHX::Encrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = m_expKey.size() - 5;
	int keyCtr = -1;

	// input round
	UInt128 R0(Input, InOffset);
	UInt128 R1(Input, InOffset + 16);
	UInt128 R2(Input, InOffset + 32);
	UInt128 R3(Input, InOffset + 48);
	UInt128::Transpose(R0, R1, R2, R3);

	// process 8 round blocks
	do
	{
		R0 ^= UInt128(m_expKey[++keyCtr]);
		R1 ^= UInt128(m_expKey[++keyCtr]);
		R2 ^= UInt128(m_expKey[++keyCtr]);
		R3 ^= UInt128(m_expKey[++keyCtr]);
		Sb0(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt128(m_expKey[++keyCtr]);
		R1 ^= UInt128(m_expKey[++keyCtr]);
		R2 ^= UInt128(m_expKey[++keyCtr]);
		R3 ^= UInt128(m_expKey[++keyCtr]);
		Sb1(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt128(m_expKey[++keyCtr]);
		R1 ^= UInt128(m_expKey[++keyCtr]);
		R2 ^= UInt128(m_expKey[++keyCtr]);
		R3 ^= UInt128(m_expKey[++keyCtr]);
		Sb2(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt128(m_expKey[++keyCtr]);
		R1 ^= UInt128(m_expKey[++keyCtr]);
		R2 ^= UInt128(m_expKey[++keyCtr]);
		R3 ^= UInt128(m_expKey[++keyCtr]);
		Sb3(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt128(m_expKey[++keyCtr]);
		R1 ^= UInt128(m_expKey[++keyCtr]);
		R2 ^= UInt128(m_expKey[++keyCtr]);
		R3 ^= UInt128(m_expKey[++keyCtr]);
		Sb4(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt128(m_expKey[++keyCtr]);
		R1 ^= UInt128(m_expKey[++keyCtr]);
		R2 ^= UInt128(m_expKey[++keyCtr]);
		R3 ^= UInt128(m_expKey[++keyCtr]);
		Sb5(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt128(m_expKey[++keyCtr]);
		R1 ^= UInt128(m_expKey[++keyCtr]);
		R2 ^= UInt128(m_expKey[++keyCtr]);
		R3 ^= UInt128(m_expKey[++keyCtr]);
		Sb6(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt128(m_expKey[++keyCtr]);
		R1 ^= UInt128(m_expKey[++keyCtr]);
		R2 ^= UInt128(m_expKey[++keyCtr]);
		R3 ^= UInt128(m_expKey[++keyCtr]);
		Sb7(R0, R1, R2, R3);

		// skip on last block
		if (keyCtr != LRD)
			LinearTransform64(R0, R1, R2, R3);
	} 
	while (keyCtr != LRD);

	// last round
	R0 ^= UInt128(m_expKey[++keyCtr]);
	R1 ^= UInt128(m_expKey[++keyCtr]);
	R2 ^= UInt128(m_expKey[++keyCtr]);
	R3 ^= UInt128(m_expKey[++keyCtr]);

	UInt128::Transpose(R0, R1, R2, R3);
	R0.StoreLE(Output, OutOffset);
	R1.StoreLE(Output, OutOffset + 16);
	R2.StoreLE(Output, OutOffset + 32);
	R3.StoreLE(Output, OutOffset + 48);
}

void SHX::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = m_expKey.size() - 5;
	int keyCtr = -1;

	// input round
	UInt256 R0(Input, InOffset);
	UInt256 R1(Input, InOffset + 32);
	UInt256 R2(Input, InOffset + 64);
	UInt256 R3(Input, InOffset + 96);
	UInt256::Transpose(R0, R1, R2, R3);

	// process 8 round blocks
	do
	{
		R0 ^= UInt256(m_expKey[++keyCtr]);
		R1 ^= UInt256(m_expKey[++keyCtr]);
		R2 ^= UInt256(m_expKey[++keyCtr]);
		R3 ^= UInt256(m_expKey[++keyCtr]);
		Sb0(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt256(m_expKey[++keyCtr]);
		R1 ^= UInt256(m_expKey[++keyCtr]);
		R2 ^= UInt256(m_expKey[++keyCtr]);
		R3 ^= UInt256(m_expKey[++keyCtr]);
		Sb1(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt256(m_expKey[++keyCtr]);
		R1 ^= UInt256(m_expKey[++keyCtr]);
		R2 ^= UInt256(m_expKey[++keyCtr]);
		R3 ^= UInt256(m_expKey[++keyCtr]);
		Sb2(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt256(m_expKey[++keyCtr]);
		R1 ^= UInt256(m_expKey[++keyCtr]);
		R2 ^= UInt256(m_expKey[++keyCtr]);
		R3 ^= UInt256(m_expKey[++keyCtr]);
		Sb3(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt256(m_expKey[++keyCtr]);
		R1 ^= UInt256(m_expKey[++keyCtr]);
		R2 ^= UInt256(m_expKey[++keyCtr]);
		R3 ^= UInt256(m_expKey[++keyCtr]);
		Sb4(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt256(m_expKey[++keyCtr]);
		R1 ^= UInt256(m_expKey[++keyCtr]);
		R2 ^= UInt256(m_expKey[++keyCtr]);
		R3 ^= UInt256(m_expKey[++keyCtr]);
		Sb5(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt256(m_expKey[++keyCtr]);
		R1 ^= UInt256(m_expKey[++keyCtr]);
		R2 ^= UInt256(m_expKey[++keyCtr]);
		R3 ^= UInt256(m_expKey[++keyCtr]);
		Sb6(R0, R1, R2, R3);
		LinearTransform64(R0, R1, R2, R3);

		R0 ^= UInt256(m_expKey[++keyCtr]);
		R1 ^= UInt256(m_expKey[++keyCtr]);
		R2 ^= UInt256(m_expKey[++keyCtr]);
		R3 ^= UInt256(m_expKey[++keyCtr]);
		Sb7(R0, R1, R2, R3);

		// skip on last block
		if (keyCtr != LRD)
			LinearTransform64(R0, R1, R2, R3);
	} while (keyCtr != LRD);

	// last round
	R0 ^= UInt256(m_expKey[++keyCtr]);
	R1 ^= UInt256(m_expKey[++keyCtr]);
	R2 ^= UInt256(m_expKey[++keyCtr]);
	R3 ^= UInt256(m_expKey[++keyCtr]);

	UInt256::Transpose(R0, R1, R2, R3);
	R0.StoreLE(Output, OutOffset);
	R1.StoreLE(Output, OutOffset + 32);
	R2.StoreLE(Output, OutOffset + 64);
	R3.StoreLE(Output, OutOffset + 96);
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
		m_kdfKeySize = DigestFromName::GetBlockSize(m_kdfEngineType);
		// calculate max saturation of entropy when distribution code is used as key extension; subtract hash finalizer code + 1 byte HKDF counter
		m_kdfInfoMax = m_kdfKeySize - (DigestFromName::GetPaddingSize(m_kdfEngineType) + 1);
		m_legalKeySizes.resize(3);
		// min allowable HMAC key
		m_legalKeySizes[0] = SymmetricKeySize(DigestFromName::GetDigestSize(m_kdfEngineType), BLOCK_SIZE, m_kdfInfoMax);
		// best size, no ipad/opad zero-byte mix in HMAC
		m_legalKeySizes[1] = SymmetricKeySize(m_kdfKeySize, BLOCK_SIZE, m_kdfInfoMax);
		// triggers HKDF Extract
		m_legalKeySizes[2] = SymmetricKeySize(m_kdfKeySize * 2, BLOCK_SIZE, m_kdfInfoMax);
	}
}

NAMESPACE_BLOCKEND