#include "AHX.h"
#include "HKDF.h"
#include "HMAC.h"
#include "IntUtils.h"
#include "DigestFromName.h"
#include <wmmintrin.h>

NAMESPACE_BLOCK

void AHX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt16(Input, 0, Output, 0);
}

void AHX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt16(Input, InOffset, Output, OutOffset);
}

void AHX::Destroy()
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

void AHX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt16(Input, 0, Output, 0);
}

void AHX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt16(Input, InOffset, Output, OutOffset);
}

void AHX::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
	int dgtsze = GetIkmSize(m_kdfEngineType);
	const std::vector<byte> &key = KeyParam.Key();
	std::string msg = "Invalid key size! Key must be either 16, 24, 32, 64 bytes or, a multiple of the hkdf hash output size.";

	if (key.size() < m_legalKeySizes[0])
		throw CryptoSymmetricCipherException("RHX:Initialize", msg);
	if (dgtsze != 0 && key.size() > m_legalKeySizes[3] && (key.size() % dgtsze) != 0)
		throw CryptoSymmetricCipherException("RHX:Initialize", msg);

	for (size_t i = 0; i < m_legalKeySizes.size(); ++i)
	{
		if (key.size() == m_legalKeySizes[i])
			break;
		if (i == m_legalKeySizes.size() - 1)
			throw CryptoSymmetricCipherException("RHX:Initialize", msg);
	}

	// get the kdf digest engine
	if (m_kdfEngineType != CEX::Enumeration::Digests::None)
	{
		if (key.size() < m_ikmSize)
			throw CryptoSymmetricCipherException("RHX:Initialize", "Invalid key! HKDF extended mode requires key be at least hash output size.");

		m_kdfEngine = GetDigest(m_kdfEngineType);
	}

	m_isEncryption = Encryption;
	// expand the key
	ExpandKey(Encryption, key);
	// ready to transform data
	m_isInitialized = true;
}

void AHX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (m_isEncryption)
		EncryptBlock(Input, Output);
	else
		DecryptBlock(Input, Output);
}

void AHX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		EncryptBlock(Input, InOffset, Output, OutOffset);
	else
		DecryptBlock(Input, InOffset, Output, OutOffset);
}

// *** Key Schedule *** //

void AHX::ExpandKey(bool Encryption, const std::vector<byte> &Key)
{
	if (m_kdfEngineType != CEX::Enumeration::Digests::None)
	{
		// hkdf key expansion
		SecureExpand(Key);
	}
	else
	{
		// standard rijndael key expansion + k512
		StandardExpand(Key);
	}

	// inverse cipher
	if (!Encryption)
	{
		size_t i, j;

		std::swap(m_expKey[0], m_expKey[m_expKey.size() - 1]);

		for (i = 1, j = m_expKey.size() - 2; i < j; ++i, --j)
		{
			__m128i temp = _mm_aesimc_si128(m_expKey[i]);
			m_expKey[i] = _mm_aesimc_si128(m_expKey[j]);
			m_expKey[j] = temp;
		}

		m_expKey[i] = _mm_aesimc_si128(m_expKey[i]);
	}
}

void AHX::SecureExpand(const std::vector<byte> &Key)
{
	// block and key in 32 bit words
	size_t blkWords = 4;
	// expanded key size
	size_t keySize = (blkWords * (m_dfnRounds + 1)) / 4;
	// kdf return array
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

	// HKDF generator expands array 
	CEX::Mac::HMAC hmac(m_kdfEngine);
	CEX::Generator::HKDF gen(&hmac);
	gen.Initialize(kdfSalt, kdfKey, m_hkdfInfo);
	gen.Generate(rawKey);
	// initialize working key
	m_expKey.resize(keySize);
	// copy bytes to working key
	memcpy(&m_expKey[0], &rawKey[0], keyBytes);
}

void AHX::StandardExpand(const std::vector<byte> &Key)
{
	// block in 32 bit words
	size_t blkWords = m_blockSize / 4;
	// key in 32 bit words
	size_t keyWords = Key.size() / 4;
	// rounds calculation, 512 gets 22 rounds
	m_dfnRounds = (blkWords == 8 && keyWords != 16) ? 14 : keyWords + 6;
	// setup expanded key
	m_expKey.resize((blkWords * (m_dfnRounds + 1)) / 4);

	if (keyWords == 16)
	{
		m_expKey[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Key.data()));
		m_expKey[1] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Key.data() + 16));
		m_expKey[2] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Key.data() + 32));
		m_expKey[3] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Key.data() + 48));

		m_expKey[4] = _mm_aeskeygenassist_si128(m_expKey[3], 0x01);
		ExpandRotBlock(m_expKey, 4, 4);
		ExpandSubBlock(m_expKey, 5, 4);
		m_expKey[6] = _mm_aeskeygenassist_si128(m_expKey[5], 0x02);
		ExpandRotBlock(m_expKey, 6, 4);
		ExpandSubBlock(m_expKey, 7, 4);
		m_expKey[8] = _mm_aeskeygenassist_si128(m_expKey[7], 0x04);
		ExpandRotBlock(m_expKey, 8, 4);
		ExpandSubBlock(m_expKey, 9, 4);
		m_expKey[10] = _mm_aeskeygenassist_si128(m_expKey[9], 0x08);
		ExpandRotBlock(m_expKey, 10, 4);
		ExpandSubBlock(m_expKey, 11, 4);
		m_expKey[12] = _mm_aeskeygenassist_si128(m_expKey[11], 0x10);
		ExpandRotBlock(m_expKey, 12, 4);
		ExpandSubBlock(m_expKey, 13, 4);
		m_expKey[14] = _mm_aeskeygenassist_si128(m_expKey[13], 0x20);
		ExpandRotBlock(m_expKey, 14, 4);
		ExpandSubBlock(m_expKey, 15, 4);
		m_expKey[16] = _mm_aeskeygenassist_si128(m_expKey[15], 0x40);
		ExpandRotBlock(m_expKey, 16, 4);
		ExpandSubBlock(m_expKey, 17, 4);
		m_expKey[18] = _mm_aeskeygenassist_si128(m_expKey[17], 0x80);
		ExpandRotBlock(m_expKey, 18, 4);
		ExpandSubBlock(m_expKey, 19, 4);
		m_expKey[20] = _mm_aeskeygenassist_si128(m_expKey[19], 0x1b);
		ExpandRotBlock(m_expKey, 20, 4);
		ExpandSubBlock(m_expKey, 21, 4);
		m_expKey[22] = _mm_aeskeygenassist_si128(m_expKey[21], 0x36);
		ExpandRotBlock(m_expKey, 22, 4);
	}
	else if (keyWords == 8)
	{
		m_expKey[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Key.data()));
		m_expKey[1] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Key.data() + 16));
		m_expKey[2] = _mm_aeskeygenassist_si128(m_expKey[1], 0x01);

		ExpandRotBlock(m_expKey, 2, 2);
		ExpandSubBlock(m_expKey, 3, 2);
		m_expKey[4] = _mm_aeskeygenassist_si128(m_expKey[3], 0x02);
		ExpandRotBlock(m_expKey, 4, 2);
		ExpandSubBlock(m_expKey, 5, 2);
		m_expKey[6] = _mm_aeskeygenassist_si128(m_expKey[5], 0x04);
		ExpandRotBlock(m_expKey, 6, 2);
		ExpandSubBlock(m_expKey, 7, 2);
		m_expKey[8] = _mm_aeskeygenassist_si128(m_expKey[7], 0x08);
		ExpandRotBlock(m_expKey, 8, 2);
		ExpandSubBlock(m_expKey, 9, 2);
		m_expKey[10] = _mm_aeskeygenassist_si128(m_expKey[9], 0x10);
		ExpandRotBlock(m_expKey, 10, 2);
		ExpandSubBlock(m_expKey, 11, 2);
		m_expKey[12] = _mm_aeskeygenassist_si128(m_expKey[11], 0x20);
		ExpandRotBlock(m_expKey, 12, 2);
		ExpandSubBlock(m_expKey, 13, 2);
		m_expKey[14] = _mm_aeskeygenassist_si128(m_expKey[13], 0x40);
		ExpandRotBlock(m_expKey, 14, 2);
	}
	else if (keyWords == 6)
	{
		__m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Key.data()));
		__m128i K1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Key.data() + 8));
		K1 = _mm_srli_si128(K1, 8);

		m_expKey[0] = K0;
		m_expKey[1] = K1;
		ExpandRotBlock(m_expKey, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x01), 24);
		ExpandRotBlock(m_expKey, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x02), 48);
		ExpandRotBlock(m_expKey, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x04), 72);
		ExpandRotBlock(m_expKey, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x08), 96);
		ExpandRotBlock(m_expKey, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x10), 120);
		ExpandRotBlock(m_expKey, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x20), 144);
		ExpandRotBlock(m_expKey, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x40), 168);
		ExpandRotBlock(m_expKey, &K0, &K1, _mm_aeskeygenassist_si128(K1, 0x80), 192);
	}
	else
	{
		m_expKey[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Key.data()));
		m_expKey[1] = _mm_aeskeygenassist_si128(m_expKey[0], 0x01);
		ExpandRotBlock(m_expKey, 1, 1);
		m_expKey[2] = _mm_aeskeygenassist_si128(m_expKey[1], 0x02);
		ExpandRotBlock(m_expKey, 2, 1);
		m_expKey[3] = _mm_aeskeygenassist_si128(m_expKey[2], 0x04);
		ExpandRotBlock(m_expKey, 3, 1);
		m_expKey[4] = _mm_aeskeygenassist_si128(m_expKey[3], 0x08);
		ExpandRotBlock(m_expKey, 4, 1);
		m_expKey[5] = _mm_aeskeygenassist_si128(m_expKey[4], 0x10);
		ExpandRotBlock(m_expKey, 5, 1);
		m_expKey[6] = _mm_aeskeygenassist_si128(m_expKey[5], 0x20);
		ExpandRotBlock(m_expKey, 6, 1);
		m_expKey[7] = _mm_aeskeygenassist_si128(m_expKey[6], 0x40);
		ExpandRotBlock(m_expKey, 7, 1);
		m_expKey[8] = _mm_aeskeygenassist_si128(m_expKey[7], 0x80);
		ExpandRotBlock(m_expKey, 8, 1);
		m_expKey[9] = _mm_aeskeygenassist_si128(m_expKey[8], 0x1b);
		ExpandRotBlock(m_expKey, 9, 1);
		m_expKey[10] = _mm_aeskeygenassist_si128(m_expKey[9], 0x36);
		ExpandRotBlock(m_expKey, 10, 1);
	}
}

void AHX::ExpandRotBlock(std::vector<__m128i> &Key, __m128i* K1, __m128i* K2, __m128i KR, size_t Offset)
{
	__m128i key1 = *K1;
	__m128i key2 = *K2;

	KR = _mm_shuffle_epi32(KR, _MM_SHUFFLE(1, 1, 1, 1));
	key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
	key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
	key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
	key1 = _mm_xor_si128(key1, KR);

	*K1 = key1;

	memcpy(((byte*)m_expKey.data() + Offset), &key1, 16);

	if (Offset == 192 && Key.size() == 13)
		return;

	key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
	key2 = _mm_xor_si128(key2, _mm_shuffle_epi32(key1, _MM_SHUFFLE(3, 3, 3, 3)));
	*K2 = key2;

	Offset += 16;
	uint32_t tmp = _mm_cvtsi128_si32(key2);

	memcpy((byte*)m_expKey.data() + Offset, &tmp, 4);
	Offset += 4;
	tmp = _mm_cvtsi128_si32(_mm_srli_si128(key2, 4));
	memcpy((byte*)m_expKey.data() + Offset, &tmp, 4);
}

void AHX::ExpandRotBlock(std::vector<__m128i> &Key, size_t Index, size_t Offset)
{
	__m128i pkb = Key[Index - Offset];
	Key[Index] = _mm_shuffle_epi32(Key[Index], 0xff);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	Key[Index] = _mm_xor_si128(pkb, Key[Index]);
}

void AHX::ExpandSubBlock(std::vector<__m128i> &Key, size_t Index, size_t Offset)
{
	__m128i pkb = Key[Index - Offset];
	Key[Index] = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(Key[Index - 1], 0x0), 0xaa);
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	pkb = _mm_xor_si128(pkb, _mm_slli_si128(pkb, 0x4));
	Key[Index] = _mm_xor_si128(pkb, Key[Index]);
}

// *** Rounds Processing *** //

void AHX::Decrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = m_expKey.size() - 2;
	size_t keyCtr = 0;

	__m128i temp = _mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset]);
	temp = _mm_xor_si128(temp, m_expKey[keyCtr]);

	while (keyCtr != LRD)
		temp = _mm_aesdec_si128(temp, m_expKey[++keyCtr]);

	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset], _mm_aesdeclast_si128(temp, m_expKey[++keyCtr]));
}

void AHX::Encrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = m_expKey.size() - 2;
	size_t keyCtr = 0;

	__m128i temp = _mm_loadu_si128((const __m128i*)(const void*)&Input[InOffset]);
	temp = _mm_xor_si128(temp, m_expKey[keyCtr]);

	while (keyCtr != LRD)
		temp = _mm_aesenc_si128(temp, m_expKey[++keyCtr]);

	_mm_storeu_si128((__m128i*)(void*)&Output[OutOffset], _mm_aesenclast_si128(temp, m_expKey[++keyCtr]));
}

// *** Helpers *** //

int AHX::GetIkmSize(CEX::Enumeration::Digests DigestType)
{
	return CEX::Helper::DigestFromName::GetDigestSize(DigestType);
}

CEX::Digest::IDigest* AHX::GetDigest(CEX::Enumeration::Digests DigestType)
{
	try
	{
		return CEX::Helper::DigestFromName::GetInstance(DigestType);
	}
	catch (...)
	{
		throw CryptoSymmetricCipherException("CipherStream:KdfEngine", "The digest could not be instantiated!");
	}
}

NAMESPACE_BLOCKEND