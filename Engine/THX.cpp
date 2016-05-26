#include "THX.h"
#include "Twofish.h"
#include "HKDF.h"
#include "HMAC.h"
#include "IntUtils.h"
#include "DigestFromName.h"

NAMESPACE_BLOCK

void THX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt16(Input, 0, Output, 0);
}

void THX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Decrypt16(Input, InOffset, Output, OutOffset);
}

void THX::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_dfnRounds = 0;
		m_ikmSize = 0;
		m_isEncryption = false;
		m_isInitialized = false;

		CEX::Utility::IntUtils::ClearVector(m_expKey);
		CEX::Utility::IntUtils::ClearVector(m_sprBox);
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

void THX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt16(Input, 0, Output, 0);
}

void THX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	Encrypt16(Input, InOffset, Output, OutOffset);
}

void THX::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
	int dgtsze = GetIkmSize(m_kdfEngineType);
	const std::vector<byte> &key = KeyParam.Key();
	std::string msg = "Invalid key size! Key must be either 16, 24, 32, 64 bytes or, a multiple of the hkdf hash output size.";

	if (key.size() < m_legalKeySizes[0])
		throw CryptoSymmetricCipherException("THX:Initialize", msg);
	if (key.size() > m_legalKeySizes[3] && (key.size() % dgtsze) != 0)
		throw CryptoSymmetricCipherException("THX:Initialize", msg);

	for (size_t i = 0; i < m_legalKeySizes.size(); ++i)
	{
		if (key.size() == m_legalKeySizes[i])
			break;
		if (i == m_legalKeySizes.size() - 1)
			throw CryptoSymmetricCipherException("THX:Initialize", msg);
	}

	// get the kdf digest engine
	if (m_kdfEngineType != CEX::Enumeration::Digests::None)
	{
		if (key.size() < m_ikmSize)
			throw CryptoSymmetricCipherException("THX:Initialize", "Invalid key! HKDF extended mode requires key be at least hash output size.");

		m_kdfEngine = GetDigest(m_kdfEngineType);
	}

	m_isEncryption = Encryption;
	// expand the key
	ExpandKey(key);
	// ready to transform data
	m_isInitialized = true;
}

void THX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (m_isEncryption)
		EncryptBlock(Input, Output);
	else
		DecryptBlock(Input, Output);
}

void THX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		EncryptBlock(Input, InOffset, Output, OutOffset);
	else
		DecryptBlock(Input, InOffset, Output, OutOffset);
}

void THX::ExpandKey(const std::vector<byte> &Key)
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
}

void THX::SecureExpand(const std::vector<byte> &Key)
{
	size_t k64Cnt = 4;
	size_t keyCtr = 0;
	size_t keySize = m_dfnRounds * 2 + 8;
	size_t kbtSize = keySize * 4;
	uint Y0, Y1, Y2, Y3;
	std::vector<byte> rawKey(kbtSize, 0);
	std::vector<byte> sbKey(16, 0);
	std::vector<uint> eKm(k64Cnt, 0);
	std::vector<uint> oKm(k64Cnt, 0);
	std::vector<uint> wK(keySize, 0);
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

	// copy bytes to working key
	memcpy(&wK[0], &rawKey[0], kbtSize);

	for (uint i = 0; i < k64Cnt; i++)
	{
		// round key material
		eKm[i] = CEX::Utility::IntUtils::BytesToLe32(rawKey, keyCtr);
		keyCtr += 4;
		oKm[i] = CEX::Utility::IntUtils::BytesToLe32(rawKey, keyCtr);
		keyCtr += 4;
		// sbox key material
		CEX::Utility::IntUtils::Le32ToBytes(MDSEncode(eKm[i], oKm[i]), sbKey, ((k64Cnt * 4) - 4) - (i * 4));
	}

	keyCtr = 0;

	while (keyCtr < KEY_BITS)
	{
		Y0 = Y1 = Y2 = Y3 = (uint)keyCtr;

		Y0 = (byte)Q1[Y0] ^ sbKey[12];
		Y1 = (byte)Q0[Y1] ^ sbKey[13];
		Y2 = (byte)Q0[Y2] ^ sbKey[14];
		Y3 = (byte)Q1[Y3] ^ sbKey[15];

		Y0 = (byte)Q1[Y0] ^ sbKey[8];
		Y1 = (byte)Q1[Y1] ^ sbKey[9];
		Y2 = (byte)Q0[Y2] ^ sbKey[10];
		Y3 = (byte)Q0[Y3] ^ sbKey[11];

		// sbox members as MDS matrix multiplies 
		m_sprBox[keyCtr * 2] = MDS0[(byte)Q0[(byte)Q0[Y0] ^ sbKey[4]] ^ sbKey[0]];
		m_sprBox[keyCtr * 2 + 1] = MDS1[(byte)Q0[Q1[Y1] ^ sbKey[5]] ^ sbKey[1]];
		m_sprBox[keyCtr * 2 + 0x200] = MDS2[(byte)Q1[(byte)Q0[Y2] ^ sbKey[6]] ^ sbKey[2]];
		m_sprBox[keyCtr++ * 2 + 0x201] = MDS3[(byte)Q1[(byte)Q1[Y3] ^ sbKey[7]] ^ sbKey[3]];
	}

	// key processed
	m_expKey = wK;
}

void THX::StandardExpand(const std::vector<byte> &Key)
{
	size_t k64Cnt = (Key.size() / 8);
	size_t kmLen = k64Cnt > 4 ? 8 : 4;
	size_t keyCtr = 0;
	uint A, B, Q;
	uint Y0, Y1, Y2, Y3;
	std::vector<uint> eKm(kmLen, 0);
	std::vector<uint> oKm(kmLen, 0);
	std::vector<byte> sbKey(Key.size() == 64 ? 32 : 16, 0);
	std::vector<uint> wK(m_dfnRounds * 2 + 8, 0);

	// CHANGE: 512 key gets 4 extra rounds
	m_dfnRounds = (Key.size() == 64) ? 20 : ROUNDS16;

	for (size_t i = 0; i < k64Cnt; ++i)
	{
		// round key material
		eKm[i] = CEX::Utility::IntUtils::BytesToLe32(Key, keyCtr);
		keyCtr += 4;
		oKm[i] = CEX::Utility::IntUtils::BytesToLe32(Key, keyCtr);
		keyCtr += 4;
		// sbox key material
		CEX::Utility::IntUtils::Le32ToBytes(MDSEncode(eKm[i], oKm[i]), sbKey, ((k64Cnt * 4) - 4) - (i * 4));
	}

	keyCtr = 0;

	while (keyCtr < KEY_BITS)
	{
		// create the expanded keys
		if (keyCtr < (int)(wK.size() / 2))
		{
			Q = (uint)(keyCtr * SK_STEP);
			A = Mix32(Q, eKm, k64Cnt);
			B = Mix32(Q + SK_BUMP, oKm, k64Cnt);
			B = B << 8 | (uint)(B >> 24);
			A += B;
			wK[keyCtr * 2] = A;
			A += B;
			wK[keyCtr * 2 + 1] = A << SK_ROTL | (long)(A >> (32 - SK_ROTL));
		}

		// gen s-box members
		Y0 = Y1 = Y2 = Y3 = (uint)keyCtr;

		// 512 key
		if (Key.size() == 64)
		{
			Y0 = (byte)Q1[Y0] ^ sbKey[28];
			Y1 = (byte)Q0[Y1] ^ sbKey[29];
			Y2 = (byte)Q0[Y2] ^ sbKey[30];
			Y3 = (byte)Q1[Y3] ^ sbKey[31];

			Y0 = (byte)Q1[Y0] ^ sbKey[24];
			Y1 = (byte)Q1[Y1] ^ sbKey[25];
			Y2 = (byte)Q0[Y2] ^ sbKey[26];
			Y3 = (byte)Q0[Y3] ^ sbKey[27];

			Y0 = (byte)Q0[Y0] ^ sbKey[20];
			Y1 = (byte)Q1[Y1] ^ sbKey[21];
			Y2 = (byte)Q1[Y2] ^ sbKey[22];
			Y3 = (byte)Q0[Y3] ^ sbKey[23];

			Y0 = (byte)Q0[Y0] ^ sbKey[16];
			Y1 = (byte)Q0[Y1] ^ sbKey[17];
			Y2 = (byte)Q1[Y2] ^ sbKey[18];
			Y3 = (byte)Q1[Y3] ^ sbKey[19];
		}
		// 256 key
		if (Key.size() > 24)
		{
			Y0 = (byte)Q1[Y0] ^ sbKey[12];
			Y1 = (byte)Q0[Y1] ^ sbKey[13];
			Y2 = (byte)Q0[Y2] ^ sbKey[14];
			Y3 = (byte)Q1[Y3] ^ sbKey[15];
		}
		// 192 key
		if (Key.size() > 16)
		{
			Y0 = (byte)Q1[Y0] ^ sbKey[8];
			Y1 = (byte)Q1[Y1] ^ sbKey[9];
			Y2 = (byte)Q0[Y2] ^ sbKey[10];
			Y3 = (byte)Q0[Y3] ^ sbKey[11];
		}

		// sbox members as MDS matrix multiplies 
		m_sprBox[keyCtr * 2] = MDS0[(byte)Q0[(byte)Q0[Y0] ^ sbKey[4]] ^ sbKey[0]];
		m_sprBox[keyCtr * 2 + 1] = MDS1[(byte)Q0[Q1[Y1] ^ sbKey[5]] ^ sbKey[1]];
		m_sprBox[(keyCtr * 2) + 0x200] = MDS2[(byte)Q1[(byte)Q0[Y2] ^ sbKey[6]] ^ sbKey[2]];
		m_sprBox[keyCtr++ * 2 + 0x201] = MDS3[(byte)Q1[(byte)Q1[Y3] ^ sbKey[7]] ^ sbKey[3]];
	}

	// expanded key
	m_expKey = wK;
}

// *** Rounds Processing *** //

void THX::Decrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = 8;
	size_t keyCtr = 4;
	uint X2 = CEX::Utility::IntUtils::BytesToLe32(Input, InOffset) ^ m_expKey[keyCtr];
	uint X3 = CEX::Utility::IntUtils::BytesToLe32(Input, InOffset + 4) ^ m_expKey[++keyCtr];
	uint X0 = CEX::Utility::IntUtils::BytesToLe32(Input, InOffset + 8) ^ m_expKey[++keyCtr];
	uint X1 = CEX::Utility::IntUtils::BytesToLe32(Input, InOffset + 12) ^ m_expKey[++keyCtr];
	uint T0, T1;

	keyCtr = m_expKey.size();
	do
	{
		// round 1
		T0 = Fe0(X2);
		T1 = Fe3(X3);
		X1 ^= T0 + 2 * T1 + m_expKey[--keyCtr];
		X0 = (X0 << 1 | (X0 >> 31)) ^ (T0 + T1 + m_expKey[--keyCtr]);
		X1 = (X1 >> 1) | X1 << 31;
		// round 2
		T0 = Fe0(X0);
		T1 = Fe3(X1);
		X3 ^= T0 + 2 * T1 + m_expKey[--keyCtr];
		X2 = (X2 << 1 | (X2 >> 31)) ^ (T0 + T1 + m_expKey[--keyCtr]);
		X3 = (X3 >> 1) | X3 << 31;

	} while (keyCtr != LRD);

	keyCtr = 0;
	CEX::Utility::IntUtils::Le32ToBytes(X0 ^ m_expKey[keyCtr], Output, OutOffset);
	CEX::Utility::IntUtils::Le32ToBytes(X1 ^ m_expKey[++keyCtr], Output, OutOffset + 4);
	CEX::Utility::IntUtils::Le32ToBytes(X2 ^ m_expKey[++keyCtr], Output, OutOffset + 8);
	CEX::Utility::IntUtils::Le32ToBytes(X3 ^ m_expKey[++keyCtr], Output, OutOffset + 12);
}

void THX::Encrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = m_expKey.size() - 1;
	size_t keyCtr = 0;
	uint X0 = CEX::Utility::IntUtils::BytesToLe32(Input, InOffset) ^ m_expKey[keyCtr];
	uint X1 = CEX::Utility::IntUtils::BytesToLe32(Input, InOffset + 4) ^ m_expKey[++keyCtr];
	uint X2 = CEX::Utility::IntUtils::BytesToLe32(Input, InOffset + 8) ^ m_expKey[++keyCtr];
	uint X3 = CEX::Utility::IntUtils::BytesToLe32(Input, InOffset + 12) ^ m_expKey[++keyCtr];
	uint T0, T1;

	keyCtr = 7;
	do
	{
		T0 = Fe0(X0);
		T1 = Fe3(X1);
		X2 ^= T0 + T1 + m_expKey[++keyCtr];
		X2 = (X2 >> 1) | X2 << 31;
		X3 = (X3 << 1 | (X3 >> 31)) ^ (T0 + 2 * T1 + m_expKey[++keyCtr]);

		T0 = Fe0(X2);
		T1 = Fe3(X3);
		X0 ^= T0 + T1 + m_expKey[++keyCtr];
		X0 = (X0 >> 1) | X0 << 31;
		X1 = (X1 << 1 | (X1 >> 31)) ^ (T0 + 2 * T1 + m_expKey[++keyCtr]);

	} while (keyCtr != LRD);

	keyCtr = 4;
	CEX::Utility::IntUtils::Le32ToBytes(X2 ^ m_expKey[keyCtr], Output, OutOffset);
	CEX::Utility::IntUtils::Le32ToBytes(X3 ^ m_expKey[++keyCtr], Output, OutOffset + 4);
	CEX::Utility::IntUtils::Le32ToBytes(X0 ^ m_expKey[++keyCtr], Output, OutOffset + 8);
	CEX::Utility::IntUtils::Le32ToBytes(X1 ^ m_expKey[++keyCtr], Output, OutOffset + 12);
}

// *** Helpers *** //

uint THX::MDSEncode(uint K0, uint K1)
{
	uint b = ((K1 >> 24) & 0xff);
	uint g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	uint g3 = ((b >> 1) ^ ((b & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ g2;
	uint rt = ((K1 << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);

	b = ((rt >> 24) & 0xff);
	g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	g3 = ((b >> 1) ^ ((b & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ g2;
	rt = ((rt << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
	b = ((rt >> 24) & 0xff);
	g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	g3 = ((b >> 1) ^ ((b & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ g2;
	rt = ((rt << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
	b = ((rt >> 24) & 0xff);
	g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	g3 = ((b >> 1) ^ ((b & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ g2;
	rt = ((rt << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
	rt ^= K0;
	b = ((rt >> 24) & 0xff);
	g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	g3 = ((b >> 1) ^ ((b & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ g2;
	rt = ((rt << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
	b = ((rt >> 24) & 0xff);
	g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	g3 = ((b >> 1) ^ ((b & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ g2;
	rt = ((rt << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
	b = ((rt >> 24) & 0xff);
	g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	g3 = ((b >> 1) ^ ((b & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ g2;
	rt = ((rt << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
	b = ((rt >> 24) & 0xff);
	g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
	g3 = ((b >> 1) ^ ((b & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0)) ^ g2;
	rt = ((rt << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);

	return rt;
}

CEX::Digest::IDigest* THX::GetDigest(CEX::Enumeration::Digests DigestType)
{
	try
	{
		return CEX::Helper::DigestFromName::GetInstance(DigestType);
	}
	catch (...)
	{
		throw CryptoSymmetricCipherException("CipherStream:GetKeyEngine", "The digest could not be instantiated!");
	}
}

int THX::GetIkmSize(CEX::Enumeration::Digests DigestType)
{
	return CEX::Helper::DigestFromName::GetDigestSize(DigestType);
}

uint THX::Mix32(const uint X, const std::vector<uint> &Key, const size_t Count)
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
	return MDS0[(byte)Q0[(byte)Q0[Y0] ^ (byte)Key[1]] ^ (byte)Key[0]] ^
		MDS1[(byte)Q0[(byte)Q1[Y1] ^ (byte)(Key[1] >> 8)] ^ (byte)(Key[0] >> 8)] ^
		MDS2[(byte)Q1[(byte)Q0[Y2] ^ (byte)(Key[1] >> 16)] ^ (byte)(Key[0] >> 16)] ^
		MDS3[(byte)Q1[(byte)Q1[Y3] ^ (byte)(Key[1] >> 24)] ^ (byte)(Key[0] >> 24)];
}

NAMESPACE_BLOCKEND