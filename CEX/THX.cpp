#include "THX.h"
#include "Twofish.h"
#include "DigestFromName.h"
#include "HKDF.h"
#include "HMAC.h"
#include "IntUtils.h"
#if defined(HAS_AVX)
#	include "UInt256.h"
#elif defined(HAS_MINSSE)
#	include "UInt128.h"
#endif

NAMESPACE_BLOCK

using CEX::Utility::IntUtils;

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

		IntUtils::ClearVector(m_expKey);
		IntUtils::ClearVector(m_sBox);
		IntUtils::ClearVector(m_hkdfInfo);
		IntUtils::ClearVector(m_legalKeySizes);
		IntUtils::ClearVector(m_legalRounds);

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
	uint dgtsze = GetIkmSize(m_kdfEngineType);

#if defined(DEBUGASSERT_ENABLED)
	assert(KeyParam.Key().size() >= m_legalKeySizes[0] && KeyParam.Key().size() <= m_legalKeySizes[m_legalKeySizes.size() - 1]);
	if (dgtsze != 0)
		assert(KeyParam.Key().size() % dgtsze == 0);
	assert(KeyParam.Key().size() >= m_ikmSize);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
	std::string msg = "Invalid key size! Key must be either 16, 24, 32, 64 bytes or, a multiple of the hkdf hash output size.";
	if (KeyParam.Key().size() < m_legalKeySizes[0])
		throw CryptoSymmetricCipherException("THX:Initialize", msg);
	if (KeyParam.Key().size() > m_legalKeySizes[3] && (KeyParam.Key().size() % dgtsze) != 0)
		throw CryptoSymmetricCipherException("THX:Initialize", msg);

	for (size_t i = 0; i < m_legalKeySizes.size(); ++i)
	{
		if (KeyParam.Key().size() == m_legalKeySizes[i])
			break;
		if (i == m_legalKeySizes.size() - 1)
			throw CryptoSymmetricCipherException("THX:Initialize", msg);
	}
	if (m_kdfEngineType != CEX::Enumeration::Digests::None)
	{
		if (KeyParam.Key().size() < m_ikmSize)
			throw CryptoSymmetricCipherException("THX:Initialize", "Invalid key! HKDF extended mode requires key be at least hash output size.");
	}
#endif

	if (m_kdfEngineType != CEX::Enumeration::Digests::None)
		m_kdfEngine = GetDigest(m_kdfEngineType);

	m_isEncryption = Encryption;
	// expand the key
	ExpandKey(KeyParam.Key());
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

void THX::Transform64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt64(Input, InOffset, Output, OutOffset);
	else
		Decrypt64(Input, InOffset, Output, OutOffset);
}

void THX::Transform128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (m_isEncryption)
		Encrypt128(Input, InOffset, Output, OutOffset);
	else
		Decrypt128(Input, InOffset, Output, OutOffset);
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
	// ToDo: look into some changes
	// 1) Pull the sbox key directly from the kdf and remove(?) sbox premix stage
	// 2) Store sbox key and calculate sbox member on the fly when sse/avx enabled(?) test performance
	// 3) If (2) is a significant gain, sbox becomes fallback when intrinsics are not available

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
		eKm[i] = IntUtils::BytesToLe32(rawKey, keyCtr);
		keyCtr += 4;
		oKm[i] = IntUtils::BytesToLe32(rawKey, keyCtr);
		keyCtr += 4;
		// sbox key material
		IntUtils::Le32ToBytes(EncodeMDS(eKm[i], oKm[i]), sbKey, ((k64Cnt * 4) - 4) - (i * 4));
	}

	keyCtr = 0;
	std::vector<uint> sMix(4);

	while (keyCtr != KEY_BITS)
	{
		Y0 = Y1 = Y2 = Y3 = (uint)keyCtr;
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
		eKm[i] = IntUtils::BytesToLe32(Key, keyCtr);
		keyCtr += 4;
		oKm[i] = IntUtils::BytesToLe32(Key, keyCtr);
		keyCtr += 4;
		// sbox key material
		IntUtils::Le32ToBytes(EncodeMDS(eKm[i], oKm[i]), sbKey, ((k64Cnt * 4) - 4) - (i * 4));
	}

	// gen s-box members
	keyCtr = Y0 = Y1 = Y2 = Y3 = 0;
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
			wK[keyCtr * 2 + 1] = A << SK_ROTL | (uint)(A >> (32 - SK_ROTL));
		}

		Y0 = Y1 = Y2 = Y3 = (uint)keyCtr;
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

void THX::Decrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = 8;
	size_t keyCtr = 4;
	uint X2 = IntUtils::BytesToLe32(Input, InOffset) ^ m_expKey[keyCtr];
	uint X3 = IntUtils::BytesToLe32(Input, InOffset + 4) ^ m_expKey[++keyCtr];
	uint X0 = IntUtils::BytesToLe32(Input, InOffset + 8) ^ m_expKey[++keyCtr];
	uint X1 = IntUtils::BytesToLe32(Input, InOffset + 12) ^ m_expKey[++keyCtr];
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
	while (keyCtr != LRD);

	keyCtr = 0;
	IntUtils::Le32ToBytes(X0 ^ m_expKey[keyCtr], Output, OutOffset);
	IntUtils::Le32ToBytes(X1 ^ m_expKey[++keyCtr], Output, OutOffset + 4);
	IntUtils::Le32ToBytes(X2 ^ m_expKey[++keyCtr], Output, OutOffset + 8);
	IntUtils::Le32ToBytes(X3 ^ m_expKey[++keyCtr], Output, OutOffset + 12);
}

void THX::Decrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(HAS_MINSSE) && !defined(HAS_AVX)

	const size_t LRD = 8;
	size_t keyCtr = 4;

	// input round
	CEX::Numeric::UInt128 X2(Input, InOffset);
	CEX::Numeric::UInt128 X3(Input, InOffset + 16);
	CEX::Numeric::UInt128 X0(Input, InOffset + 32);
	CEX::Numeric::UInt128 X1(Input, InOffset + 48);
	CEX::Numeric::UInt128::Transpose(X2, X3, X0, X1);
	CEX::Numeric::UInt128 T0, T1;
	CEX::Numeric::UInt128 N2(2);

	X2 ^= m_expKey[keyCtr];
	X3 ^= m_expKey[++keyCtr];
	X0 ^= m_expKey[++keyCtr];
	X1 ^= m_expKey[++keyCtr];

	keyCtr = m_expKey.size();
	do
	{
		T0 = I4Fe0(X2, m_sBox);
		T1 = I4Fe3(X3, m_sBox);
		X1 ^= T0 + N2 * T1 + m_expKey[--keyCtr];
		X0 = (X0 << 1) | (X0 >> 31);
		X0 ^= (T0 + T1 + m_expKey[--keyCtr]);
		X1 = (X1 >> 1) | (X1 << 31);

		T0 = I4Fe0(X0, m_sBox);
		T1 = I4Fe3(X1, m_sBox);
		X3 ^= T0 + N2 * T1 + m_expKey[--keyCtr];
		X2 = (X2 << 1) | (X2 >> 31);
		X2 ^= (T0 + T1 + m_expKey[--keyCtr]);
		X3 = (X3 >> 1) | (X3 << 31);
	} 
	while (keyCtr != LRD);

	// last round
	keyCtr = 0;
	X0 ^= m_expKey[keyCtr];
	X1 ^= m_expKey[++keyCtr];
	X2 ^= m_expKey[++keyCtr];
	X3 ^= m_expKey[++keyCtr];

	CEX::Numeric::UInt128::Transpose(X0, X1, X2, X3);
	X0.StoreLE(Output, OutOffset);
	X1.StoreLE(Output, OutOffset + 16);
	X2.StoreLE(Output, OutOffset + 32);
	X3.StoreLE(Output, OutOffset + 48);

#else

	Decrypt16(Input, InOffset, Output, OutOffset);
	Decrypt16(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt16(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt16(Input, InOffset + 48, Output, OutOffset + 48);

#endif
}

void THX::Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(HAS_AVX)

	const size_t LRD = 8;
	size_t keyCtr = 4;

	// input round
	CEX::Numeric::UInt256 X2(Input, InOffset);
	CEX::Numeric::UInt256 X3(Input, InOffset + 32);
	CEX::Numeric::UInt256 X0(Input, InOffset + 64);
	CEX::Numeric::UInt256 X1(Input, InOffset + 96);
	CEX::Numeric::UInt256::Transpose(X2, X3, X0, X1);
	CEX::Numeric::UInt256 T0, T1;
	CEX::Numeric::UInt256 N2(2);

	X2 ^= m_expKey[keyCtr];
	X3 ^= m_expKey[++keyCtr];
	X0 ^= m_expKey[++keyCtr];
	X1 ^= m_expKey[++keyCtr];

	keyCtr = m_expKey.size();
	do
	{
		T0 = I8Fe0(X2, m_sBox);
		T1 = I8Fe3(X3, m_sBox);
		X1 ^= T0 + N2 * T1 + m_expKey[--keyCtr];
		X0 = (X0 << 1) | (X0 >> 31);
		X0 ^= (T0 + T1 + m_expKey[--keyCtr]);
		X1 = (X1 >> 1) | (X1 << 31);

		T0 = I8Fe0(X0, m_sBox);
		T1 = I8Fe3(X1, m_sBox);
		X3 ^= T0 + N2 * T1 + m_expKey[--keyCtr];
		X2 = (X2 << 1) | (X2 >> 31);
		X2 ^= (T0 + T1 + m_expKey[--keyCtr]);
		X3 = (X3 >> 1) | (X3 << 31);
	} 
	while (keyCtr != LRD);

	// last round
	keyCtr = 0;
	X0 ^= m_expKey[keyCtr];
	X1 ^= m_expKey[++keyCtr];
	X2 ^= m_expKey[++keyCtr];
	X3 ^= m_expKey[++keyCtr];

	CEX::Numeric::UInt256::Transpose(X0, X1, X2, X3);
	X0.StoreLE(Output, OutOffset);
	X1.StoreLE(Output, OutOffset + 32);
	X2.StoreLE(Output, OutOffset + 64);
	X3.StoreLE(Output, OutOffset + 96);

#else

	Decrypt16(Input, InOffset, Output, OutOffset);
	Decrypt16(Input, InOffset + 16, Output, OutOffset + 16);
	Decrypt16(Input, InOffset + 32, Output, OutOffset + 32);
	Decrypt16(Input, InOffset + 48, Output, OutOffset + 48);
	Decrypt16(Input, InOffset + 64, Output, OutOffset + 64);
	Decrypt16(Input, InOffset + 80, Output, OutOffset + 80);
	Decrypt16(Input, InOffset + 96, Output, OutOffset + 96);
	Decrypt16(Input, InOffset + 112, Output, OutOffset + 112);

#endif
}

void THX::Encrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = m_expKey.size() - 1;
	size_t keyCtr = 0;
	uint X0 = IntUtils::BytesToLe32(Input, InOffset) ^ m_expKey[keyCtr];
	uint X1 = IntUtils::BytesToLe32(Input, InOffset + 4) ^ m_expKey[++keyCtr];
	uint X2 = IntUtils::BytesToLe32(Input, InOffset + 8) ^ m_expKey[++keyCtr];
	uint X3 = IntUtils::BytesToLe32(Input, InOffset + 12) ^ m_expKey[++keyCtr];
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
	while (keyCtr != LRD);

	keyCtr = 4;
	X2 ^= m_expKey[keyCtr];
	X3 ^= m_expKey[++keyCtr];
	X0 ^= m_expKey[++keyCtr];
	X1 ^= m_expKey[++keyCtr];

	IntUtils::Le32ToBytes(X2, Output, OutOffset);
	IntUtils::Le32ToBytes(X3, Output, OutOffset + 4);
	IntUtils::Le32ToBytes(X0, Output, OutOffset + 8);
	IntUtils::Le32ToBytes(X1, Output, OutOffset + 12);
}

void THX::Encrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(HAS_MINSSE) && !defined(HAS_AVX)

	const size_t LRD = m_expKey.size() - 1;
	size_t keyCtr = 0;

	// input round
	CEX::Numeric::UInt128 X0(Input, InOffset);
	CEX::Numeric::UInt128 X1(Input, InOffset + 16);
	CEX::Numeric::UInt128 X2(Input, InOffset + 32);
	CEX::Numeric::UInt128 X3(Input, InOffset + 48);
	CEX::Numeric::UInt128::Transpose(X0, X1, X2, X3);
	CEX::Numeric::UInt128 T0, T1;
	CEX::Numeric::UInt128 N2(2);

	X0 ^= m_expKey[keyCtr];
	X1 ^= m_expKey[++keyCtr];
	X2 ^= m_expKey[++keyCtr];
	X3 ^= m_expKey[++keyCtr];
	
	keyCtr = 7;
	do
	{
		T0 = I4Fe0(X0, m_sBox);
		T1 = I4Fe3(X1, m_sBox);
		X2 ^= T0 + T1 + m_expKey[++keyCtr];
		X2 = (X2 >> 1) | (X2 << 31);
		X3 = (X3 << 1) | (X3 >> 31);
		X3 ^= (T0 + N2 * T1 + m_expKey[++keyCtr]);

		T0 = I4Fe0(X2, m_sBox);
		T1 = I4Fe3(X3, m_sBox);
		X0 ^= T0 + T1 + m_expKey[++keyCtr];
		X0 = (X0 >> 1) | (X0 << 31);
		X1 = ((X1 << 1) | (X1 >> 31));
		X1 ^= (T0 + N2 * T1 + m_expKey[++keyCtr]);
	} 
	while (keyCtr != LRD);

	// last round
	keyCtr = 4;
	X2 ^= m_expKey[keyCtr];
	X3 ^= m_expKey[++keyCtr];
	X0 ^= m_expKey[++keyCtr];
	X1 ^= m_expKey[++keyCtr];

	CEX::Numeric::UInt128::Transpose(X2, X3, X0, X1);
	X2.StoreLE(Output, OutOffset);
	X3.StoreLE(Output, OutOffset + 16);
	X0.StoreLE(Output, OutOffset + 32);
	X1.StoreLE(Output, OutOffset + 48);

#else

	Encrypt16(Input, InOffset, Output, OutOffset);
	Encrypt16(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt16(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt16(Input, InOffset + 48, Output, OutOffset + 48);

#endif
}

void THX::Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(HAS_AVX)

	const size_t LRD = m_expKey.size() - 1;
	size_t keyCtr = 0;

	// input round
	CEX::Numeric::UInt256 X0(Input, InOffset);
	CEX::Numeric::UInt256 X1(Input, InOffset + 32);
	CEX::Numeric::UInt256 X2(Input, InOffset + 64);
	CEX::Numeric::UInt256 X3(Input, InOffset + 96);
	CEX::Numeric::UInt256::Transpose(X0, X1, X2, X3);
	CEX::Numeric::UInt256 T0, T1;
	CEX::Numeric::UInt256 N2(2);

	X0 ^= m_expKey[keyCtr];
	X1 ^= m_expKey[++keyCtr];
	X2 ^= m_expKey[++keyCtr];
	X3 ^= m_expKey[++keyCtr];

	keyCtr = 7;
	do
	{
		T0 = I8Fe0(X0, m_sBox);
		T1 = I8Fe3(X1, m_sBox);
		X2 ^= T0 + T1 + m_expKey[++keyCtr];
		X2 = (X2 >> 1) | (X2 << 31);
		X3 = (X3 << 1) | (X3 >> 31);
		X3 ^= (T0 + N2 * T1 + m_expKey[++keyCtr]);

		T0 = I8Fe0(X2, m_sBox);
		T1 = I8Fe3(X3, m_sBox);
		X0 ^= T0 + T1 + m_expKey[++keyCtr];
		X0 = (X0 >> 1) | (X0 << 31);
		X1 = ((X1 << 1) | (X1 >> 31));
		X1 ^= (T0 + N2 * T1 + m_expKey[++keyCtr]);
	} 
	while (keyCtr != LRD);

	// last round
	keyCtr = 4;
	X2 ^= m_expKey[keyCtr];
	X3 ^= m_expKey[++keyCtr];
	X0 ^= m_expKey[++keyCtr];
	X1 ^= m_expKey[++keyCtr];

	CEX::Numeric::UInt256::Transpose(X2, X3, X0, X1);
	X2.StoreLE(Output, OutOffset);
	X3.StoreLE(Output, OutOffset + 32);
	X0.StoreLE(Output, OutOffset + 64);
	X1.StoreLE(Output, OutOffset + 96);

#else

	Encrypt16(Input, InOffset, Output, OutOffset);
	Encrypt16(Input, InOffset + 16, Output, OutOffset + 16);
	Encrypt16(Input, InOffset + 32, Output, OutOffset + 32);
	Encrypt16(Input, InOffset + 48, Output, OutOffset + 48);
	Encrypt16(Input, InOffset + 64, Output, OutOffset + 64);
	Encrypt16(Input, InOffset + 80, Output, OutOffset + 80);
	Encrypt16(Input, InOffset + 96, Output, OutOffset + 96);
	Encrypt16(Input, InOffset + 112, Output, OutOffset + 112);

#endif
}

//~~~Helpers~~~//

uint THX::EncodeMDS(uint K0, uint K1)
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

CEX::Digest::IDigest* THX::GetDigest(CEX::Enumeration::Digests DigestType)
{
	try
	{
		return CEX::Helper::DigestFromName::GetInstance(DigestType);
	}
	catch (...)
	{
#if defined(DEBUGASSERT_ENABLED)
		assert("THX:GetDigest The digest could not be instantiated!");
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoSymmetricCipherException("THX:GetDigest", "The digest could not be instantiated!");
#else
		return 0;
#endif
	}
}

uint THX::GetIkmSize(CEX::Enumeration::Digests DigestType)
{
	return CEX::Helper::DigestFromName::GetDigestSize(DigestType);
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

NAMESPACE_BLOCKEND