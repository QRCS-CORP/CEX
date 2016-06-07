#include "RHX.h"
#include "Rijndael.h"
#include "DigestFromName.h"
#include "HKDF.h"
#include "HMAC.h"
#include "IntUtils.h"

NAMESPACE_BLOCK

void RHX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (m_blockSize == BLOCK16)
		Decrypt16(Input, 0, Output, 0);
	else
		Decrypt32(Input, 0, Output, 0);
}

void RHX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_blockSize == BLOCK16)
		Decrypt16(Input, InOffset, Output, OutOffset);
	else
		Decrypt32(Input, InOffset, Output, OutOffset);
}

void RHX::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
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

void RHX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (m_blockSize == BLOCK16)
		Encrypt16(Input, 0, Output, 0);
	else
		Encrypt32(Input, 0, Output, 0);
}

void RHX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_blockSize == BLOCK16)
		Encrypt16(Input, InOffset, Output, OutOffset);
	else
		Encrypt32(Input, InOffset, Output, OutOffset);
}

void RHX::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
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

void RHX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (m_isEncryption)
		EncryptBlock(Input, Output);
	else
		DecryptBlock(Input, Output);
}

void RHX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		EncryptBlock(Input, InOffset, Output, OutOffset);
	else
		DecryptBlock(Input, InOffset, Output, OutOffset);
}

// *** Key Schedule *** //

void RHX::ExpandKey(bool Encryption, const std::vector<byte> &Key)
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
		size_t blkWords = m_blockSize / 4;

		// reverse key
		for (size_t i = 0, k = m_expKey.size() - blkWords; i < k; i += blkWords, k -= blkWords)
		{
			for (size_t j = 0; j < blkWords; j++) //0-112, 1-113.. 7-119
			{
				uint temp = m_expKey[i + j];
				m_expKey[i + j] = m_expKey[k + j];
				m_expKey[k + j] = temp;
			}
		}
		// sbox inversion
		for (size_t i = blkWords; i < m_expKey.size() - blkWords; i++)
		{
			m_expKey[i] = IT0[SBox[(m_expKey[i] >> 24)]] ^
				IT1[SBox[(byte)(m_expKey[i] >> 16)]] ^
				IT2[SBox[(byte)(m_expKey[i] >> 8)]] ^
				IT3[SBox[(byte)m_expKey[i]]];
		}
	}
}

void RHX::SecureExpand(const std::vector<byte> &Key)
{
	// block and key in 32 bit words
	size_t blkWords = m_blockSize / 4;
	// expanded key size
	size_t keySize = blkWords * (m_dfnRounds + 1);
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
	m_expKey.resize(keySize, 0);
	// copy bytes to working key
	memcpy(&m_expKey[0], &rawKey[0], keyBytes);
}

void RHX::StandardExpand(const std::vector<byte> &Key)
{
	// block in 32 bit words
	size_t blkWords = m_blockSize / 4;
	// key in 32 bit words
	size_t keyWords = Key.size() / 4;
	// rounds calculation, 512 gets 22 rounds
	m_dfnRounds = (blkWords == 8 && keyWords != 16) ? 14 : keyWords + 6;
	// setup expanded key
	m_expKey.resize(blkWords * (m_dfnRounds + 1), 0);

	if (keyWords == 16)
	{
		m_expKey[0] = CEX::Utility::IntUtils::BytesToBe32(Key, 0);
		m_expKey[1] = CEX::Utility::IntUtils::BytesToBe32(Key, 4);
		m_expKey[2] = CEX::Utility::IntUtils::BytesToBe32(Key, 8);
		m_expKey[3] = CEX::Utility::IntUtils::BytesToBe32(Key, 12);
		m_expKey[4] = CEX::Utility::IntUtils::BytesToBe32(Key, 16);
		m_expKey[5] = CEX::Utility::IntUtils::BytesToBe32(Key, 20);
		m_expKey[6] = CEX::Utility::IntUtils::BytesToBe32(Key, 24);
		m_expKey[7] = CEX::Utility::IntUtils::BytesToBe32(Key, 28);
		m_expKey[8] = CEX::Utility::IntUtils::BytesToBe32(Key, 32);
		m_expKey[9] = CEX::Utility::IntUtils::BytesToBe32(Key, 36);
		m_expKey[10] = CEX::Utility::IntUtils::BytesToBe32(Key, 40);
		m_expKey[11] = CEX::Utility::IntUtils::BytesToBe32(Key, 44);
		m_expKey[12] = CEX::Utility::IntUtils::BytesToBe32(Key, 48);
		m_expKey[13] = CEX::Utility::IntUtils::BytesToBe32(Key, 52);
		m_expKey[14] = CEX::Utility::IntUtils::BytesToBe32(Key, 56);
		m_expKey[15] = CEX::Utility::IntUtils::BytesToBe32(Key, 60);

		// k512 R: 16,24,32,40,48,56,64,72,80,88, S: 20,28,36,44,52,60,68,76,84
		ExpandRotBlock(m_expKey, 16, 16, 1);
		ExpandSubBlock(m_expKey, 20, 16);
		ExpandRotBlock(m_expKey, 24, 16, 2);
		ExpandSubBlock(m_expKey, 28, 16);
		ExpandRotBlock(m_expKey, 32, 16, 3);
		ExpandSubBlock(m_expKey, 36, 16);
		ExpandRotBlock(m_expKey, 40, 16, 4);
		ExpandSubBlock(m_expKey, 44, 16);
		ExpandRotBlock(m_expKey, 48, 16, 5);
		ExpandSubBlock(m_expKey, 52, 16);
		ExpandRotBlock(m_expKey, 56, 16, 6);
		ExpandSubBlock(m_expKey, 60, 16);
		ExpandRotBlock(m_expKey, 64, 16, 7);
		ExpandSubBlock(m_expKey, 68, 16);
		ExpandRotBlock(m_expKey, 72, 16, 8);
		ExpandSubBlock(m_expKey, 76, 16);
		ExpandRotBlock(m_expKey, 80, 16, 9);
		ExpandSubBlock(m_expKey, 84, 16);
		ExpandRotBlock(m_expKey, 88, 16, 10);

		if (blkWords == 8)
		{
			ExpandSubBlock(m_expKey, 92, 16);
			ExpandRotBlock(m_expKey, 96, 16, 11);
			ExpandSubBlock(m_expKey, 100, 16);
			ExpandRotBlock(m_expKey, 104, 16, 12);
			ExpandSubBlock(m_expKey, 108, 16);
			ExpandRotBlock(m_expKey, 112, 16, 13);
			ExpandSubBlock(m_expKey, 116, 16);
			ExpandRotBlock(m_expKey, 120, 16, 14);
			ExpandSubBlock(m_expKey, 124, 16);
			ExpandRotBlock(m_expKey, 128, 16, 15);
			ExpandSubBlock(m_expKey, 132, 16);
			ExpandRotBlock(m_expKey, 136, 16, 16);
			ExpandSubBlock(m_expKey, 140, 16);
			ExpandRotBlock(m_expKey, 144, 16, 17);
			ExpandSubBlock(m_expKey, 148, 16);
			ExpandRotBlock(m_expKey, 152, 16, 18);
			ExpandSubBlock(m_expKey, 156, 16);
			ExpandRotBlock(m_expKey, 160, 16, 19);
			ExpandSubBlock(m_expKey, 164, 16);
			ExpandRotBlock(m_expKey, 168, 16, 20);
			ExpandSubBlock(m_expKey, 172, 16);
			ExpandRotBlock(m_expKey, 176, 16, 21);
			ExpandSubBlock(m_expKey, 180, 16);
		}
	}
	else if (keyWords == 8)
	{
		m_expKey[0] = CEX::Utility::IntUtils::BytesToBe32(Key, 0);
		m_expKey[1] = CEX::Utility::IntUtils::BytesToBe32(Key, 4);
		m_expKey[2] = CEX::Utility::IntUtils::BytesToBe32(Key, 8);
		m_expKey[3] = CEX::Utility::IntUtils::BytesToBe32(Key, 12);
		m_expKey[4] = CEX::Utility::IntUtils::BytesToBe32(Key, 16);
		m_expKey[5] = CEX::Utility::IntUtils::BytesToBe32(Key, 20);
		m_expKey[6] = CEX::Utility::IntUtils::BytesToBe32(Key, 24);
		m_expKey[7] = CEX::Utility::IntUtils::BytesToBe32(Key, 28);

		// k256 R: 8,16,24,32,40,48,56 S: 12,20,28,36,44,52
		ExpandRotBlock(m_expKey, 8, 8, 1);
		ExpandSubBlock(m_expKey, 12, 8);
		ExpandRotBlock(m_expKey, 16, 8, 2);
		ExpandSubBlock(m_expKey, 20, 8);
		ExpandRotBlock(m_expKey, 24, 8, 3);
		ExpandSubBlock(m_expKey, 28, 8);
		ExpandRotBlock(m_expKey, 32, 8, 4);
		ExpandSubBlock(m_expKey, 36, 8);
		ExpandRotBlock(m_expKey, 40, 8, 5);
		ExpandSubBlock(m_expKey, 44, 8);
		ExpandRotBlock(m_expKey, 48, 8, 6);
		ExpandSubBlock(m_expKey, 52, 8);
		ExpandRotBlock(m_expKey, 56, 8, 7);

		if (blkWords == 8)
		{
			ExpandSubBlock(m_expKey, 60, 8);
			ExpandRotBlock(m_expKey, 64, 8, 8);
			ExpandSubBlock(m_expKey, 68, 8);
			ExpandRotBlock(m_expKey, 72, 8, 9);
			ExpandSubBlock(m_expKey, 76, 8);
			ExpandRotBlock(m_expKey, 80, 8, 10);
			ExpandSubBlock(m_expKey, 84, 8);
			ExpandRotBlock(m_expKey, 88, 8, 11);
			ExpandSubBlock(m_expKey, 92, 8);
			ExpandRotBlock(m_expKey, 96, 8, 12);
			ExpandSubBlock(m_expKey, 100, 8);
			ExpandRotBlock(m_expKey, 104, 8, 13);
			ExpandSubBlock(m_expKey, 108, 8);
			ExpandRotBlock(m_expKey, 112, 8, 14);
			ExpandSubBlock(m_expKey, 116, 8);
		}
	}
	else if (keyWords == 6)
	{
		m_expKey[0] = CEX::Utility::IntUtils::BytesToBe32(Key, 0);
		m_expKey[1] = CEX::Utility::IntUtils::BytesToBe32(Key, 4);
		m_expKey[2] = CEX::Utility::IntUtils::BytesToBe32(Key, 8);
		m_expKey[3] = CEX::Utility::IntUtils::BytesToBe32(Key, 12);
		m_expKey[4] = CEX::Utility::IntUtils::BytesToBe32(Key, 16);
		m_expKey[5] = CEX::Utility::IntUtils::BytesToBe32(Key, 20);

		// // k192 R: 6,12,18,24,30,36,42,48
		ExpandRotBlock(m_expKey, 6, 6, 1);
		m_expKey[10] = m_expKey[4] ^ m_expKey[9];
		m_expKey[11] = m_expKey[5] ^ m_expKey[10];
		ExpandRotBlock(m_expKey, 12, 6, 2);
		m_expKey[16] = m_expKey[10] ^ m_expKey[15];
		m_expKey[17] = m_expKey[11] ^ m_expKey[16];
		ExpandRotBlock(m_expKey, 18, 6, 3);
		m_expKey[22] = m_expKey[16] ^ m_expKey[21];
		m_expKey[23] = m_expKey[17] ^ m_expKey[22];
		ExpandRotBlock(m_expKey, 24, 6, 4);
		m_expKey[28] = m_expKey[22] ^ m_expKey[27];
		m_expKey[29] = m_expKey[23] ^ m_expKey[28];
		ExpandRotBlock(m_expKey, 30, 6, 5);
		m_expKey[34] = m_expKey[28] ^ m_expKey[33];
		m_expKey[35] = m_expKey[29] ^ m_expKey[34];
		ExpandRotBlock(m_expKey, 36, 6, 6);
		m_expKey[40] = m_expKey[34] ^ m_expKey[39];
		m_expKey[41] = m_expKey[35] ^ m_expKey[40];
		ExpandRotBlock(m_expKey, 42, 6, 7);
		m_expKey[46] = m_expKey[40] ^ m_expKey[45];
		m_expKey[47] = m_expKey[41] ^ m_expKey[46];
		ExpandRotBlock(m_expKey, 48, 6, 8);

		if (blkWords == 8)
		{
			m_expKey[52] = m_expKey[46] ^ m_expKey[51];
			m_expKey[53] = m_expKey[47] ^ m_expKey[52];
			ExpandRotBlock(m_expKey, 54, 6, 9);
			m_expKey[58] = m_expKey[52] ^ m_expKey[57];
			m_expKey[59] = m_expKey[53] ^ m_expKey[58];
			ExpandRotBlock(m_expKey, 60, 6, 10);
			m_expKey[64] = m_expKey[58] ^ m_expKey[63];
			m_expKey[65] = m_expKey[59] ^ m_expKey[64];
			ExpandRotBlock(m_expKey, 66, 6, 11);
			m_expKey[70] = m_expKey[64] ^ m_expKey[69];
			m_expKey[71] = m_expKey[65] ^ m_expKey[70];
			ExpandRotBlock(m_expKey, 72, 6, 12);
			m_expKey[76] = m_expKey[70] ^ m_expKey[75];
			m_expKey[77] = m_expKey[71] ^ m_expKey[76];
			ExpandRotBlock(m_expKey, 78, 6, 13);
			m_expKey[82] = m_expKey[76] ^ m_expKey[81];
			m_expKey[83] = m_expKey[77] ^ m_expKey[82];
			ExpandRotBlock(m_expKey, 84, 6, 14);
			m_expKey[88] = m_expKey[82] ^ m_expKey[87];
			m_expKey[89] = m_expKey[83] ^ m_expKey[88];
			ExpandRotBlock(m_expKey, 90, 6, 15);
			m_expKey[94] = m_expKey[88] ^ m_expKey[93];
			m_expKey[95] = m_expKey[89] ^ m_expKey[94];
			ExpandRotBlock(m_expKey, 96, 6, 16);
			m_expKey[100] = m_expKey[94] ^ m_expKey[99];
			m_expKey[101] = m_expKey[95] ^ m_expKey[100];
			ExpandRotBlock(m_expKey, 102, 6, 17);
			m_expKey[106] = m_expKey[100] ^ m_expKey[105];
			m_expKey[107] = m_expKey[101] ^ m_expKey[106];
			ExpandRotBlock(m_expKey, 108, 6, 18);
			m_expKey[112] = m_expKey[106] ^ m_expKey[111];
			m_expKey[113] = m_expKey[107] ^ m_expKey[112];
			ExpandRotBlock(m_expKey, 114, 6, 19);
			m_expKey[118] = m_expKey[112] ^ m_expKey[117];
			m_expKey[119] = m_expKey[113] ^ m_expKey[118];
		}
	}
	else
	{
		m_expKey[0] = CEX::Utility::IntUtils::BytesToBe32(Key, 0);
		m_expKey[1] = CEX::Utility::IntUtils::BytesToBe32(Key, 4);
		m_expKey[2] = CEX::Utility::IntUtils::BytesToBe32(Key, 8);
		m_expKey[3] = CEX::Utility::IntUtils::BytesToBe32(Key, 12);

		// k128 R: 4,8,12,16,20,24,28,32,36,40
		ExpandRotBlock(m_expKey, 4, 4, 1);
		ExpandRotBlock(m_expKey, 8, 4, 2);
		ExpandRotBlock(m_expKey, 12, 4, 3);
		ExpandRotBlock(m_expKey, 16, 4, 4);
		ExpandRotBlock(m_expKey, 20, 4, 5);
		ExpandRotBlock(m_expKey, 24, 4, 6);
		ExpandRotBlock(m_expKey, 28, 4, 7);
		ExpandRotBlock(m_expKey, 32, 4, 8);
		ExpandRotBlock(m_expKey, 36, 4, 9);
		ExpandRotBlock(m_expKey, 40, 4, 10);

		if (blkWords == 8)
		{
			ExpandRotBlock(m_expKey, 44, 4, 11);
			ExpandRotBlock(m_expKey, 48, 4, 12);
			ExpandRotBlock(m_expKey, 52, 4, 13);
			ExpandRotBlock(m_expKey, 56, 4, 14);
			ExpandRotBlock(m_expKey, 60, 4, 15);
			ExpandRotBlock(m_expKey, 64, 4, 16);
			ExpandRotBlock(m_expKey, 68, 4, 17);
			ExpandRotBlock(m_expKey, 72, 4, 18);
			ExpandRotBlock(m_expKey, 76, 4, 19);
			ExpandRotBlock(m_expKey, 80, 4, 20);
			ExpandRotBlock(m_expKey, 84, 4, 21);
			ExpandRotBlock(m_expKey, 88, 4, 22);
			ExpandRotBlock(m_expKey, 92, 4, 23);
			ExpandRotBlock(m_expKey, 96, 4, 24);
			ExpandRotBlock(m_expKey, 100, 4, 25);
			ExpandRotBlock(m_expKey, 104, 4, 26);
			ExpandRotBlock(m_expKey, 108, 4, 27);
			ExpandRotBlock(m_expKey, 112, 4, 28);
			ExpandRotBlock(m_expKey, 116, 4, 29);
		}
	}
}

void RHX::ExpandRotBlock(std::vector<uint> &Key, size_t KeyIndex, size_t KeyOffset, size_t RconIndex)
{
	size_t sub = KeyIndex - KeyOffset;

	Key[KeyIndex] = Key[sub] ^ SubByte((Key[KeyIndex - 1] << 8) | ((Key[KeyIndex - 1] >> 24) & 0xFF)) ^ Rcon[RconIndex];
	// note: you can insert noise before each mix to further equalize timing, i.e: uint tmp = SubByte(Key[KeyIndex - 1]);
	Key[++KeyIndex] = Key[++sub] ^ Key[KeyIndex - 1];
	Key[++KeyIndex] = Key[++sub] ^ Key[KeyIndex - 1];
	Key[++KeyIndex] = Key[++sub] ^ Key[KeyIndex - 1];
}

void RHX::ExpandSubBlock(std::vector<uint> &Key, size_t KeyIndex, size_t KeyOffset)
{
	size_t sub = KeyIndex - KeyOffset;

	Key[KeyIndex] = SubByte(Key[KeyIndex - 1]) ^ Key[sub];
	Key[++KeyIndex] = Key[++sub] ^ Key[KeyIndex - 1];
	Key[++KeyIndex] = Key[++sub] ^ Key[KeyIndex - 1];
	Key[++KeyIndex] = Key[++sub] ^ Key[KeyIndex - 1];
}

// *** Rounds Processing *** //

void RHX::Decrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = m_expKey.size() - 5;
	size_t keyCtr = 0;

	// round 0
	uint X0 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset) ^ m_expKey[keyCtr];
	uint X1 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 4) ^ m_expKey[++keyCtr];
	uint X2 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 8) ^ m_expKey[++keyCtr];
	uint X3 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 12) ^ m_expKey[++keyCtr];

	// round 1
	uint Y0 = IT0[(X0 >> 24)] ^ IT1[(byte)(X3 >> 16)] ^ IT2[(byte)(X2 >> 8)] ^ IT3[(byte)X1] ^ m_expKey[++keyCtr];
	uint Y1 = IT0[(X1 >> 24)] ^ IT1[(byte)(X0 >> 16)] ^ IT2[(byte)(X3 >> 8)] ^ IT3[(byte)X2] ^ m_expKey[++keyCtr];
	uint Y2 = IT0[(X2 >> 24)] ^ IT1[(byte)(X1 >> 16)] ^ IT2[(byte)(X0 >> 8)] ^ IT3[(byte)X3] ^ m_expKey[++keyCtr];
	uint Y3 = IT0[(X3 >> 24)] ^ IT1[(byte)(X2 >> 16)] ^ IT2[(byte)(X1 >> 8)] ^ IT3[(byte)X0] ^ m_expKey[++keyCtr];

	// rounds loop
	while (keyCtr != LRD)
	{
		X0 = IT0[(Y0 >> 24)] ^ IT1[(byte)(Y3 >> 16)] ^ IT2[(byte)(Y2 >> 8)] ^ IT3[(byte)Y1] ^ m_expKey[++keyCtr];
		X1 = IT0[(Y1 >> 24)] ^ IT1[(byte)(Y0 >> 16)] ^ IT2[(byte)(Y3 >> 8)] ^ IT3[(byte)Y2] ^ m_expKey[++keyCtr];
		X2 = IT0[(Y2 >> 24)] ^ IT1[(byte)(Y1 >> 16)] ^ IT2[(byte)(Y0 >> 8)] ^ IT3[(byte)Y3] ^ m_expKey[++keyCtr];
		X3 = IT0[(Y3 >> 24)] ^ IT1[(byte)(Y2 >> 16)] ^ IT2[(byte)(Y1 >> 8)] ^ IT3[(byte)Y0] ^ m_expKey[++keyCtr];

		Y0 = IT0[(X0 >> 24)] ^ IT1[(byte)(X3 >> 16)] ^ IT2[(byte)(X2 >> 8)] ^ IT3[(byte)X1] ^ m_expKey[++keyCtr];
		Y1 = IT0[(X1 >> 24)] ^ IT1[(byte)(X0 >> 16)] ^ IT2[(byte)(X3 >> 8)] ^ IT3[(byte)X2] ^ m_expKey[++keyCtr];
		Y2 = IT0[(X2 >> 24)] ^ IT1[(byte)(X1 >> 16)] ^ IT2[(byte)(X0 >> 8)] ^ IT3[(byte)X3] ^ m_expKey[++keyCtr];
		Y3 = IT0[(X3 >> 24)] ^ IT1[(byte)(X2 >> 16)] ^ IT2[(byte)(X1 >> 8)] ^ IT3[(byte)X0] ^ m_expKey[++keyCtr];
	}

	// final round
	Output[OutOffset] = (byte)(ISBox[(byte)(Y0 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 1] = (byte)(ISBox[(byte)(Y3 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 2] = (byte)(ISBox[(byte)(Y2 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 3] = (byte)(ISBox[(byte)Y1] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 4] = (byte)(ISBox[(byte)(Y1 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 5] = (byte)(ISBox[(byte)(Y0 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 6] = (byte)(ISBox[(byte)(Y3 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 7] = (byte)(ISBox[(byte)Y2] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 8] = (byte)(ISBox[(byte)(Y2 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 9] = (byte)(ISBox[(byte)(Y1 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 10] = (byte)(ISBox[(byte)(Y0 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 11] = (byte)(ISBox[(byte)Y3] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 12] = (byte)(ISBox[(byte)(Y3 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 13] = (byte)(ISBox[(byte)(Y2 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 14] = (byte)(ISBox[(byte)(Y1 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 15] = (byte)(ISBox[(byte)Y0] ^ (byte)m_expKey[keyCtr]);
}

void RHX::Decrypt32(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = m_expKey.size() - 9;
	size_t keyCtr = 0;

	// round 0
	uint X0 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset) ^ m_expKey[keyCtr];
	uint X1 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 4) ^ m_expKey[++keyCtr];
	uint X2 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 8) ^ m_expKey[++keyCtr];
	uint X3 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 12) ^ m_expKey[++keyCtr];
	uint X4 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 16) ^ m_expKey[++keyCtr];
	uint X5 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 20) ^ m_expKey[++keyCtr];
	uint X6 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 24) ^ m_expKey[++keyCtr];
	uint X7 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 28) ^ m_expKey[++keyCtr];

	// round 1
	uint Y0 = IT0[(byte)(X0 >> 24)] ^ IT1[(byte)(X7 >> 16)] ^ IT2[(byte)(X5 >> 8)] ^ IT3[(byte)X4] ^ m_expKey[++keyCtr];
	uint Y1 = IT0[(byte)(X1 >> 24)] ^ IT1[(byte)(X0 >> 16)] ^ IT2[(byte)(X6 >> 8)] ^ IT3[(byte)X5] ^ m_expKey[++keyCtr];
	uint Y2 = IT0[(byte)(X2 >> 24)] ^ IT1[(byte)(X1 >> 16)] ^ IT2[(byte)(X7 >> 8)] ^ IT3[(byte)X6] ^ m_expKey[++keyCtr];
	uint Y3 = IT0[(byte)(X3 >> 24)] ^ IT1[(byte)(X2 >> 16)] ^ IT2[(byte)(X0 >> 8)] ^ IT3[(byte)X7] ^ m_expKey[++keyCtr];
	uint Y4 = IT0[(byte)(X4 >> 24)] ^ IT1[(byte)(X3 >> 16)] ^ IT2[(byte)(X1 >> 8)] ^ IT3[(byte)X0] ^ m_expKey[++keyCtr];
	uint Y5 = IT0[(byte)(X5 >> 24)] ^ IT1[(byte)(X4 >> 16)] ^ IT2[(byte)(X2 >> 8)] ^ IT3[(byte)X1] ^ m_expKey[++keyCtr];
	uint Y6 = IT0[(byte)(X6 >> 24)] ^ IT1[(byte)(X5 >> 16)] ^ IT2[(byte)(X3 >> 8)] ^ IT3[(byte)X2] ^ m_expKey[++keyCtr];
	uint Y7 = IT0[(byte)(X7 >> 24)] ^ IT1[(byte)(X6 >> 16)] ^ IT2[(byte)(X4 >> 8)] ^ IT3[(byte)X3] ^ m_expKey[++keyCtr];

	// rounds loop
	while (keyCtr != LRD)
	{
		X0 = IT0[(byte)(Y0 >> 24)] ^ IT1[(byte)(Y7 >> 16)] ^ IT2[(byte)(Y5 >> 8)] ^ IT3[(byte)Y4] ^ m_expKey[++keyCtr];
		X1 = IT0[(byte)(Y1 >> 24)] ^ IT1[(byte)(Y0 >> 16)] ^ IT2[(byte)(Y6 >> 8)] ^ IT3[(byte)Y5] ^ m_expKey[++keyCtr];
		X2 = IT0[(byte)(Y2 >> 24)] ^ IT1[(byte)(Y1 >> 16)] ^ IT2[(byte)(Y7 >> 8)] ^ IT3[(byte)Y6] ^ m_expKey[++keyCtr];
		X3 = IT0[(byte)(Y3 >> 24)] ^ IT1[(byte)(Y2 >> 16)] ^ IT2[(byte)(Y0 >> 8)] ^ IT3[(byte)Y7] ^ m_expKey[++keyCtr];
		X4 = IT0[(byte)(Y4 >> 24)] ^ IT1[(byte)(Y3 >> 16)] ^ IT2[(byte)(Y1 >> 8)] ^ IT3[(byte)Y0] ^ m_expKey[++keyCtr];
		X5 = IT0[(byte)(Y5 >> 24)] ^ IT1[(byte)(Y4 >> 16)] ^ IT2[(byte)(Y2 >> 8)] ^ IT3[(byte)Y1] ^ m_expKey[++keyCtr];
		X6 = IT0[(byte)(Y6 >> 24)] ^ IT1[(byte)(Y5 >> 16)] ^ IT2[(byte)(Y3 >> 8)] ^ IT3[(byte)Y2] ^ m_expKey[++keyCtr];
		X7 = IT0[(byte)(Y7 >> 24)] ^ IT1[(byte)(Y6 >> 16)] ^ IT2[(byte)(Y4 >> 8)] ^ IT3[(byte)Y3] ^ m_expKey[++keyCtr];

		Y0 = IT0[(byte)(X0 >> 24)] ^ IT1[(byte)(X7 >> 16)] ^ IT2[(byte)(X5 >> 8)] ^ IT3[(byte)X4] ^ m_expKey[++keyCtr];
		Y1 = IT0[(byte)(X1 >> 24)] ^ IT1[(byte)(X0 >> 16)] ^ IT2[(byte)(X6 >> 8)] ^ IT3[(byte)X5] ^ m_expKey[++keyCtr];
		Y2 = IT0[(byte)(X2 >> 24)] ^ IT1[(byte)(X1 >> 16)] ^ IT2[(byte)(X7 >> 8)] ^ IT3[(byte)X6] ^ m_expKey[++keyCtr];
		Y3 = IT0[(byte)(X3 >> 24)] ^ IT1[(byte)(X2 >> 16)] ^ IT2[(byte)(X0 >> 8)] ^ IT3[(byte)X7] ^ m_expKey[++keyCtr];
		Y4 = IT0[(byte)(X4 >> 24)] ^ IT1[(byte)(X3 >> 16)] ^ IT2[(byte)(X1 >> 8)] ^ IT3[(byte)X0] ^ m_expKey[++keyCtr];
		Y5 = IT0[(byte)(X5 >> 24)] ^ IT1[(byte)(X4 >> 16)] ^ IT2[(byte)(X2 >> 8)] ^ IT3[(byte)X1] ^ m_expKey[++keyCtr];
		Y6 = IT0[(byte)(X6 >> 24)] ^ IT1[(byte)(X5 >> 16)] ^ IT2[(byte)(X3 >> 8)] ^ IT3[(byte)X2] ^ m_expKey[++keyCtr];
		Y7 = IT0[(byte)(X7 >> 24)] ^ IT1[(byte)(X6 >> 16)] ^ IT2[(byte)(X4 >> 8)] ^ IT3[(byte)X3] ^ m_expKey[++keyCtr];
	}

	// final round
	Output[OutOffset] = (byte)(ISBox[(byte)(Y0 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 1] = (byte)(ISBox[(byte)(Y7 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 2] = (byte)(ISBox[(byte)(Y5 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 3] = (byte)(ISBox[(byte)Y4] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 4] = (byte)(ISBox[(byte)(Y1 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 5] = (byte)(ISBox[(byte)(Y0 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 6] = (byte)(ISBox[(byte)(Y6 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 7] = (byte)(ISBox[(byte)Y5] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 8] = (byte)(ISBox[(byte)(Y2 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 9] = (byte)(ISBox[(byte)(Y1 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 10] = (byte)(ISBox[(byte)(Y7 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 11] = (byte)(ISBox[(byte)Y6] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 12] = (byte)(ISBox[(byte)(Y3 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 13] = (byte)(ISBox[(byte)(Y2 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 14] = (byte)(ISBox[(byte)(Y0 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 15] = (byte)(ISBox[(byte)Y7] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 16] = (byte)(ISBox[(byte)(Y4 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 17] = (byte)(ISBox[(byte)(Y3 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 18] = (byte)(ISBox[(byte)(Y1 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 19] = (byte)(ISBox[(byte)Y0] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 20] = (byte)(ISBox[(byte)(Y5 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 21] = (byte)(ISBox[(byte)(Y4 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 22] = (byte)(ISBox[(byte)(Y2 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 23] = (byte)(ISBox[(byte)Y1] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 24] = (byte)(ISBox[(byte)(Y6 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 25] = (byte)(ISBox[(byte)(Y5 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 26] = (byte)(ISBox[(byte)(Y3 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 27] = (byte)(ISBox[(byte)Y2] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 28] = (byte)(ISBox[(byte)(Y7 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 29] = (byte)(ISBox[(byte)(Y6 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 30] = (byte)(ISBox[(byte)(Y4 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 31] = (byte)(ISBox[(byte)Y3] ^ (byte)m_expKey[keyCtr]);
}

void RHX::Encrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = m_expKey.size() - 5;
	size_t keyCtr = 0;

	// round 0
	uint X0 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset) ^ m_expKey[keyCtr];
	uint X1 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 4) ^ m_expKey[++keyCtr];
	uint X2 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 8) ^ m_expKey[++keyCtr];
	uint X3 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 12) ^ m_expKey[++keyCtr];

	// round 1
	uint Y0 = T0[(byte)(X0 >> 24)] ^ T1[(byte)(X1 >> 16)] ^ T2[(byte)(X2 >> 8)] ^ T3[(byte)X3] ^ m_expKey[++keyCtr];
	uint Y1 = T0[(byte)(X1 >> 24)] ^ T1[(byte)(X2 >> 16)] ^ T2[(byte)(X3 >> 8)] ^ T3[(byte)X0] ^ m_expKey[++keyCtr];
	uint Y2 = T0[(byte)(X2 >> 24)] ^ T1[(byte)(X3 >> 16)] ^ T2[(byte)(X0 >> 8)] ^ T3[(byte)X1] ^ m_expKey[++keyCtr];
	uint Y3 = T0[(byte)(X3 >> 24)] ^ T1[(byte)(X0 >> 16)] ^ T2[(byte)(X1 >> 8)] ^ T3[(byte)X2] ^ m_expKey[++keyCtr];

	while (keyCtr != LRD)
	{
		X0 = T0[(byte)(Y0 >> 24)] ^ T1[(byte)(Y1 >> 16)] ^ T2[(byte)(Y2 >> 8)] ^ T3[(byte)Y3] ^ m_expKey[++keyCtr];
		X1 = T0[(byte)(Y1 >> 24)] ^ T1[(byte)(Y2 >> 16)] ^ T2[(byte)(Y3 >> 8)] ^ T3[(byte)Y0] ^ m_expKey[++keyCtr];
		X2 = T0[(byte)(Y2 >> 24)] ^ T1[(byte)(Y3 >> 16)] ^ T2[(byte)(Y0 >> 8)] ^ T3[(byte)Y1] ^ m_expKey[++keyCtr];
		X3 = T0[(byte)(Y3 >> 24)] ^ T1[(byte)(Y0 >> 16)] ^ T2[(byte)(Y1 >> 8)] ^ T3[(byte)Y2] ^ m_expKey[++keyCtr];
		Y0 = T0[(byte)(X0 >> 24)] ^ T1[(byte)(X1 >> 16)] ^ T2[(byte)(X2 >> 8)] ^ T3[(byte)X3] ^ m_expKey[++keyCtr];
		Y1 = T0[(byte)(X1 >> 24)] ^ T1[(byte)(X2 >> 16)] ^ T2[(byte)(X3 >> 8)] ^ T3[(byte)X0] ^ m_expKey[++keyCtr];
		Y2 = T0[(byte)(X2 >> 24)] ^ T1[(byte)(X3 >> 16)] ^ T2[(byte)(X0 >> 8)] ^ T3[(byte)X1] ^ m_expKey[++keyCtr];
		Y3 = T0[(byte)(X3 >> 24)] ^ T1[(byte)(X0 >> 16)] ^ T2[(byte)(X1 >> 8)] ^ T3[(byte)X2] ^ m_expKey[++keyCtr];
	}

	// final round
	Output[OutOffset] = (byte)(SBox[(byte)(Y0 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 1] = (byte)(SBox[(byte)(Y1 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 2] = (byte)(SBox[(byte)(Y2 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 3] = (byte)(SBox[(byte)Y3] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 4] = (byte)(SBox[(byte)(Y1 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 5] = (byte)(SBox[(byte)(Y2 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 6] = (byte)(SBox[(byte)(Y3 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 7] = (byte)(SBox[(byte)Y0] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 8] = (byte)(SBox[(byte)(Y2 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 9] = (byte)(SBox[(byte)(Y3 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 10] = (byte)(SBox[(byte)(Y0 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 11] = (byte)(SBox[(byte)Y1] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 12] = (byte)(SBox[(byte)(Y3 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 13] = (byte)(SBox[(byte)(Y0 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 14] = (byte)(SBox[(byte)(Y1 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 15] = (byte)(SBox[(byte)Y2] ^ (byte)m_expKey[keyCtr]);
}

void RHX::Encrypt32(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = m_expKey.size() - 9;
	size_t keyCtr = 0;

	// round 0
	uint X0 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset) ^ m_expKey[keyCtr];
	uint X1 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 4) ^ m_expKey[++keyCtr];
	uint X2 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 8) ^ m_expKey[++keyCtr];
	uint X3 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 12) ^ m_expKey[++keyCtr];
	uint X4 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 16) ^ m_expKey[++keyCtr];
	uint X5 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 20) ^ m_expKey[++keyCtr];
	uint X6 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 24) ^ m_expKey[++keyCtr];
	uint X7 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 28) ^ m_expKey[++keyCtr];

	// round 1
	uint Y0 = T0[(byte)(X0 >> 24)] ^ T1[(byte)(X1 >> 16)] ^ T2[(byte)(X3 >> 8)] ^ T3[(byte)X4] ^ m_expKey[++keyCtr];
	uint Y1 = T0[(byte)(X1 >> 24)] ^ T1[(byte)(X2 >> 16)] ^ T2[(byte)(X4 >> 8)] ^ T3[(byte)X5] ^ m_expKey[++keyCtr];
	uint Y2 = T0[(byte)(X2 >> 24)] ^ T1[(byte)(X3 >> 16)] ^ T2[(byte)(X5 >> 8)] ^ T3[(byte)X6] ^ m_expKey[++keyCtr];
	uint Y3 = T0[(byte)(X3 >> 24)] ^ T1[(byte)(X4 >> 16)] ^ T2[(byte)(X6 >> 8)] ^ T3[(byte)X7] ^ m_expKey[++keyCtr];
	uint Y4 = T0[(byte)(X4 >> 24)] ^ T1[(byte)(X5 >> 16)] ^ T2[(byte)(X7 >> 8)] ^ T3[(byte)X0] ^ m_expKey[++keyCtr];
	uint Y5 = T0[(byte)(X5 >> 24)] ^ T1[(byte)(X6 >> 16)] ^ T2[(byte)(X0 >> 8)] ^ T3[(byte)X1] ^ m_expKey[++keyCtr];
	uint Y6 = T0[(byte)(X6 >> 24)] ^ T1[(byte)(X7 >> 16)] ^ T2[(byte)(X1 >> 8)] ^ T3[(byte)X2] ^ m_expKey[++keyCtr];
	uint Y7 = T0[(byte)(X7 >> 24)] ^ T1[(byte)(X0 >> 16)] ^ T2[(byte)(X2 >> 8)] ^ T3[(byte)X3] ^ m_expKey[++keyCtr];

	// rounds loop
	while (keyCtr != LRD)
	{
		X0 = T0[(byte)(Y0 >> 24)] ^ T1[(byte)(Y1 >> 16)] ^ T2[(byte)(Y3 >> 8)] ^ T3[(byte)Y4] ^ m_expKey[++keyCtr];
		X1 = T0[(byte)(Y1 >> 24)] ^ T1[(byte)(Y2 >> 16)] ^ T2[(byte)(Y4 >> 8)] ^ T3[(byte)Y5] ^ m_expKey[++keyCtr];
		X2 = T0[(byte)(Y2 >> 24)] ^ T1[(byte)(Y3 >> 16)] ^ T2[(byte)(Y5 >> 8)] ^ T3[(byte)Y6] ^ m_expKey[++keyCtr];
		X3 = T0[(byte)(Y3 >> 24)] ^ T1[(byte)(Y4 >> 16)] ^ T2[(byte)(Y6 >> 8)] ^ T3[(byte)Y7] ^ m_expKey[++keyCtr];
		X4 = T0[(byte)(Y4 >> 24)] ^ T1[(byte)(Y5 >> 16)] ^ T2[(byte)(Y7 >> 8)] ^ T3[(byte)Y0] ^ m_expKey[++keyCtr];
		X5 = T0[(byte)(Y5 >> 24)] ^ T1[(byte)(Y6 >> 16)] ^ T2[(byte)(Y0 >> 8)] ^ T3[(byte)Y1] ^ m_expKey[++keyCtr];
		X6 = T0[(byte)(Y6 >> 24)] ^ T1[(byte)(Y7 >> 16)] ^ T2[(byte)(Y1 >> 8)] ^ T3[(byte)Y2] ^ m_expKey[++keyCtr];
		X7 = T0[(byte)(Y7 >> 24)] ^ T1[(byte)(Y0 >> 16)] ^ T2[(byte)(Y2 >> 8)] ^ T3[(byte)Y3] ^ m_expKey[++keyCtr];

		Y0 = T0[(byte)(X0 >> 24)] ^ T1[(byte)(X1 >> 16)] ^ T2[(byte)(X3 >> 8)] ^ T3[(byte)X4] ^ m_expKey[++keyCtr];
		Y1 = T0[(byte)(X1 >> 24)] ^ T1[(byte)(X2 >> 16)] ^ T2[(byte)(X4 >> 8)] ^ T3[(byte)X5] ^ m_expKey[++keyCtr];
		Y2 = T0[(byte)(X2 >> 24)] ^ T1[(byte)(X3 >> 16)] ^ T2[(byte)(X5 >> 8)] ^ T3[(byte)X6] ^ m_expKey[++keyCtr];
		Y3 = T0[(byte)(X3 >> 24)] ^ T1[(byte)(X4 >> 16)] ^ T2[(byte)(X6 >> 8)] ^ T3[(byte)X7] ^ m_expKey[++keyCtr];
		Y4 = T0[(byte)(X4 >> 24)] ^ T1[(byte)(X5 >> 16)] ^ T2[(byte)(X7 >> 8)] ^ T3[(byte)X0] ^ m_expKey[++keyCtr];
		Y5 = T0[(byte)(X5 >> 24)] ^ T1[(byte)(X6 >> 16)] ^ T2[(byte)(X0 >> 8)] ^ T3[(byte)X1] ^ m_expKey[++keyCtr];
		Y6 = T0[(byte)(X6 >> 24)] ^ T1[(byte)(X7 >> 16)] ^ T2[(byte)(X1 >> 8)] ^ T3[(byte)X2] ^ m_expKey[++keyCtr];
		Y7 = T0[(byte)(X7 >> 24)] ^ T1[(byte)(X0 >> 16)] ^ T2[(byte)(X2 >> 8)] ^ T3[(byte)X3] ^ m_expKey[++keyCtr];
	}

	// final round
	Output[OutOffset] = (byte)(SBox[(byte)(Y0 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 1] = (byte)(SBox[(byte)(Y1 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 2] = (byte)(SBox[(byte)(Y3 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 3] = (byte)(SBox[(byte)Y4] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 4] = (byte)(SBox[(byte)(Y1 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 5] = (byte)(SBox[(byte)(Y2 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 6] = (byte)(SBox[(byte)(Y4 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 7] = (byte)(SBox[(byte)Y5] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 8] = (byte)(SBox[(byte)(Y2 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 9] = (byte)(SBox[(byte)(Y3 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 10] = (byte)(SBox[(byte)(Y5 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 11] = (byte)(SBox[(byte)Y6] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 12] = (byte)(SBox[(byte)(Y3 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 13] = (byte)(SBox[(byte)(Y4 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 14] = (byte)(SBox[(byte)(Y6 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 15] = (byte)(SBox[(byte)Y7] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 16] = (byte)(SBox[(byte)(Y4 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 17] = (byte)(SBox[(byte)(Y5 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 18] = (byte)(SBox[(byte)(Y7 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 19] = (byte)(SBox[(byte)Y0] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 20] = (byte)(SBox[(byte)(Y5 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 21] = (byte)(SBox[(byte)(Y6 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 22] = (byte)(SBox[(byte)(Y0 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 23] = (byte)(SBox[(byte)Y1] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 24] = (byte)(SBox[(byte)(Y6 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 25] = (byte)(SBox[(byte)(Y7 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 26] = (byte)(SBox[(byte)(Y1 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 27] = (byte)(SBox[(byte)Y2] ^ (byte)m_expKey[keyCtr]);

	Output[OutOffset + 28] = (byte)(SBox[(byte)(Y7 >> 24)] ^ (byte)(m_expKey[++keyCtr] >> 24));
	Output[OutOffset + 29] = (byte)(SBox[(byte)(Y0 >> 16)] ^ (byte)(m_expKey[keyCtr] >> 16));
	Output[OutOffset + 30] = (byte)(SBox[(byte)(Y2 >> 8)] ^ (byte)(m_expKey[keyCtr] >> 8));
	Output[OutOffset + 31] = (byte)(SBox[(byte)Y3] ^ (byte)m_expKey[keyCtr]);
}

// *** Helpers *** //

int RHX::GetIkmSize(CEX::Enumeration::Digests DigestType)
{
	return CEX::Helper::DigestFromName::GetDigestSize(DigestType);
}

CEX::Digest::IDigest* RHX::GetDigest(CEX::Enumeration::Digests DigestType)
{
	try
	{
		return CEX::Helper::DigestFromName::GetInstance(DigestType);
	}
	catch (...)
	{
		throw CryptoSymmetricCipherException("RHX:GetDigest", "The digest could not be instantiated!");
	}
}

uint RHX::SubByte(uint Rot)
{
	uint value = 0xff & Rot;
	uint result = SBox[value];
	value = 0xff & (Rot >> 8);
	result |= (uint)SBox[value] << 8;
	value = 0xff & (Rot >> 16);
	result |= (uint)SBox[value] << 16;
	value = 0xff & (Rot >> 24);
	return result | (uint)(SBox[value] << 24);
}

NAMESPACE_BLOCKEND