#include "SHX.h"
#include "Serpent.h"
#include "DigestFromName.h"
#include "HKDF.h"
#include "HMAC.h"
#include "IntUtils.h"

NAMESPACE_BLOCK

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
		m_dfnRounds = 0;
		m_ikmSize = 0;
		m_isEncryption = false;
		m_isInitialized = false;

		CEX::Utility::IntUtils::ClearVector(m_expKey);
		CEX::Utility::IntUtils::ClearVector(m_hkdfInfo);
		CEX::Utility::IntUtils::ClearVector(m_legalKeySizes);
		CEX::Utility::IntUtils::ClearVector(m_legalRounds);

		if (m_kdfEngine != 0)
		{
			m_kdfEngine->Destroy();
			if (m_destroyEngine)
				delete m_kdfEngine;
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

void SHX::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
	int dgtsze = GetIkmSize(m_kdfEngineType);
	const std::vector<byte> &key = KeyParam.Key();
	std::string msg = "Invalid key size! Key must be either 16, 24, 32, 64 bytes or, a multiple of the hkdf hash output size.";

	if (key.size() < m_legalKeySizes[0])
		throw CryptoSymmetricCipherException("SHX:Initialize", msg);
	if (key.size() > m_legalKeySizes[3] && (key.size() % dgtsze) != 0)
		throw CryptoSymmetricCipherException("SHX:Initialize", msg);

	for (size_t i = 0; i < m_legalKeySizes.size(); ++i)
	{
		if (key.size() == m_legalKeySizes[i])
			break;
		if (i == m_legalKeySizes.size() - 1)
			throw CryptoSymmetricCipherException("SHX:Initialize", msg);
	}

	// get the kdf digest engine
	if (m_kdfEngineType != CEX::Enumeration::Digests::None)
	{
		if (key.size() < m_ikmSize)
			throw CryptoSymmetricCipherException("SHX:Initialize", "Invalid key! HKDF extended mode requires key be at least hash output size.");

		m_kdfEngine = GetDigest(m_kdfEngineType);
	}

	m_isEncryption = Encryption;
	// expand the key
	ExpandKey(key);
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

// *** Key Schedule *** //

void SHX::ExpandKey(const std::vector<byte> &Key)
{
	if (m_kdfEngineType != CEX::Enumeration::Digests::None)
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
	size_t keySize = 4 * (m_dfnRounds + 1);
	// hkdf return array
	size_t keyBytes = keySize * 4;
	std::vector<byte> rawKey(keyBytes, 0);
	size_t saltSize = Key.size() - m_ikmSize;

	// hkdf input
	std::vector<byte> kdfKey(m_ikmSize, 0);
	std::vector<byte> kdfSalt(0, 0);

	// copy hkdf key and salt from user key
	memcpy(&kdfKey[0], &Key[0], m_ikmSize);
	if (saltSize > 0)
	{
		kdfSalt.resize(saltSize);
		memcpy(&kdfSalt[0], &Key[m_ikmSize], saltSize);
	}

	// HKDF generator expands array using an SHA512 HMAC
	CEX::Mac::HMAC hmac(m_kdfEngine);
	CEX::Generator::HKDF gen(&hmac);
	gen.Initialize(kdfSalt, kdfKey, m_hkdfInfo);
	gen.Generate(rawKey);

	// initialize working key
	std::vector<uint> wK(keySize, 0);
	// copy bytes to working key
	memcpy(&wK[0], &rawKey[0], keyBytes);
	// set the expanded key
	m_expKey = wK;
}

void SHX::StandardExpand(const std::vector<byte> &Key)
{
	uint cnt = 0;
	uint index = 0;
	size_t padSize = Key.size() < 32 ? 16 : Key.size() / 2;
	std::vector<uint> Wp(padSize, 0);
	size_t offset = 0;

	// CHANGE: 512 key gets 8 extra rounds
	m_dfnRounds = (Key.size() == 64) ? 40 : ROUNDS32;
	size_t keySize = 4 * (m_dfnRounds + 1);

	// step 1: reverse copy key to temp array
	for (offset = Key.size(); offset > 0; offset -= 4)
		Wp[index++] = CEX::Utility::IntUtils::BytesToBe32(Key, offset - 4);

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
			Wp[i] = CEX::Utility::IntUtils::RotateLeft((uint)(Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 8)), 11);

		// copy to expanded key
		CopyVector(Wp, 8, Wk, 0, 8);

		// step 3: calculate remainder of rounds with rotating primitive
		for (size_t i = 8; i < keySize; i++)
			Wk[i] = CEX::Utility::IntUtils::RotateLeft((uint)(Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
	}
	else
	{
		// *extended*: 64 byte key
		// step 3: rotate k into w(k) ints, with extended polynominal
		// Wp := (Wp-16 ^ Wp-13 ^ Wp-11 ^ Wp-10 ^ Wp-8 ^ Wp-5 ^ Wp-3 ^ Wp-1 ^ PHI ^ i) <<< 11
		for (size_t i = 16; i < 32; i++)
			Wp[i] = CEX::Utility::IntUtils::RotateLeft((uint)(Wp[i - 16] ^ Wp[i - 13] ^ Wp[i - 11] ^ Wp[i - 10] ^ Wp[i - 8] ^ Wp[i - 5] ^ Wp[i - 3] ^ Wp[i - 1] ^ PHI ^ (i - 16)), 11);

		// copy to expanded key
		CopyVector(Wp, 16, Wk, 0, 16);

		// step 3: calculate remainder of rounds with rotating primitive
		for (size_t i = 16; i < keySize; i++)
			Wk[i] = CEX::Utility::IntUtils::RotateLeft((uint)(Wk[i - 16] ^ Wk[i - 13] ^ Wk[i - 11] ^ Wk[i - 10] ^ Wk[i - 8] ^ Wk[i - 5] ^ Wk[i - 3] ^ Wk[i - 1] ^ PHI ^ i), 11);
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

// *** Rounds Processing *** //

void SHX::Decrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = 4;
	size_t keyCtr = m_expKey.size();

	// input round
	uint R3 = m_expKey[--keyCtr] ^ CEX::Utility::IntUtils::BytesToBe32(Input, InOffset);
	uint R2 = m_expKey[--keyCtr] ^ CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 4);
	uint R1 = m_expKey[--keyCtr] ^ CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 8);
	uint R0 = m_expKey[--keyCtr] ^ CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 12);

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

	} while (keyCtr != LRD);

	// last round
	CEX::Utility::IntUtils::Be32ToBytes(R3 ^ m_expKey[--keyCtr], Output, OutOffset);
	CEX::Utility::IntUtils::Be32ToBytes(R2 ^ m_expKey[--keyCtr], Output, OutOffset + 4);
	CEX::Utility::IntUtils::Be32ToBytes(R1 ^ m_expKey[--keyCtr], Output, OutOffset + 8);
	CEX::Utility::IntUtils::Be32ToBytes(R0 ^ m_expKey[--keyCtr], Output, OutOffset + 12);
}

void SHX::Encrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = m_expKey.size() - 5;
	int keyCtr = -1;

	// input round
	uint R0 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 12);
	uint R1 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 8);
	uint R2 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 4);
	uint R3 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset);

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

	} while (keyCtr != LRD);

	// last round
	CEX::Utility::IntUtils::Be32ToBytes(m_expKey[++keyCtr] ^ R0, Output, OutOffset + 12);
	CEX::Utility::IntUtils::Be32ToBytes(m_expKey[++keyCtr] ^ R1, Output, OutOffset + 8);
	CEX::Utility::IntUtils::Be32ToBytes(m_expKey[++keyCtr] ^ R2, Output, OutOffset + 4);
	CEX::Utility::IntUtils::Be32ToBytes(m_expKey[++keyCtr] ^ R3, Output, OutOffset);
}

/// <remarks>
/// Apply the linear transformation to the register set
/// </remarks>
void SHX::LinearTransform(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint x0 = CEX::Utility::IntUtils::RotateLeft(R0, 13);
	uint x2 = CEX::Utility::IntUtils::RotateLeft(R2, 3);
	uint x1 = R1 ^ x0 ^ x2;
	uint x3 = R3 ^ x2 ^ x0 << 3;

	R1 = CEX::Utility::IntUtils::RotateLeft(x1, 1);
	R3 = CEX::Utility::IntUtils::RotateLeft(x3, 7);
	R0 = CEX::Utility::IntUtils::RotateLeft(x0 ^ R1 ^ R3, 5);
	R2 = CEX::Utility::IntUtils::RotateLeft(x2 ^ R3 ^ (R1 << 7), 22);
}

/// <remarks>
/// Apply the inverse of the linear transformation to the register set
/// </remarks>
void SHX::InverseTransform(uint &R0, uint &R1, uint &R2, uint &R3)
{
	uint x2 = CEX::Utility::IntUtils::RotateRight(R2, 22) ^ R3 ^ (R1 << 7);
	uint x0 = CEX::Utility::IntUtils::RotateRight(R0, 5) ^ R1 ^ R3;
	uint x3 = CEX::Utility::IntUtils::RotateRight(R3, 7);
	uint x1 = CEX::Utility::IntUtils::RotateRight(R1, 1);

	R3 = x3 ^ x2 ^ x0 << 3;
	R1 = x1 ^ x0 ^ x2;
	R2 = CEX::Utility::IntUtils::RotateRight(x2, 3);
	R0 = CEX::Utility::IntUtils::RotateRight(x0, 13);
}

CEX::Digest::IDigest* SHX::GetDigest(CEX::Enumeration::Digests DigestType)
{
	try
	{
		return CEX::Helper::DigestFromName::GetInstance(DigestType);
	}
	catch (...)
	{
		throw CryptoSymmetricCipherException("SHX:GetDigest", "The digest could not be instantiated!");
	}
}

int SHX::GetIkmSize(CEX::Enumeration::Digests DigestType)
{
	return CEX::Helper::DigestFromName::GetDigestSize(DigestType);
}

NAMESPACE_BLOCKEND