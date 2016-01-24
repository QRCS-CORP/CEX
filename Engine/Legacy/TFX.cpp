#include "TFX.h"
#include "Twofish.h"
#include "IntUtils.h"

NAMESPACE_BLOCK

using CEX::Utility::IntUtils;

void TFX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt16(Input, 0, Output, 0);
}

void TFX::DecryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	Decrypt16(Input, InOffset, Output, OutOffset);
}

void TFX::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_dfnRounds = 0;
		_isEncryption = false;
		_isInitialized = false;

		IntUtils::ClearVector(_expKey);
		IntUtils::ClearVector(_sprBox);
		IntUtils::ClearVector(_legalKeySizes);
		IntUtils::ClearVector(_legalRounds);
	}
}

void TFX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt16(Input, 0, Output, 0);
}

void TFX::EncryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	Encrypt16(Input, InOffset, Output, OutOffset);
}

void TFX::Initialize(bool Encryption, const KeyParams &KeyParam)
{
	if (KeyParam.Key().size() != 16 && KeyParam.Key().size() != 24 && KeyParam.Key().size() != 32 && KeyParam.Key().size() != 64)
		throw CryptoSymmetricCipherException("TFX:Initialize", "Invalid key size! Valid sizes are 16, 24, 32 and 64 bytes.");

	_isEncryption = Encryption;
	ExpandKey(KeyParam.Key());
	_isInitialized = true;
}

void TFX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (_isEncryption)
		EncryptBlock(Input, Output);
	else
		DecryptBlock(Input, Output);
}

void TFX::Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	if (_isEncryption)
		EncryptBlock(Input, InOffset, Output, OutOffset);
	else
		DecryptBlock(Input, InOffset, Output, OutOffset);
}

// *** Key Schedule *** //

void TFX::ExpandKey(const std::vector<byte> &Key)
{
	unsigned int k64Cnt = Key.size() / 8;
	unsigned int kmLen = k64Cnt > 4 ? 8 : 4;
	unsigned int keyCtr = 0;
	uint A, B, Q;
	uint Y0, Y1, Y2, Y3;
	std::vector<uint> eKm(kmLen, 0);
	std::vector<uint> oKm(kmLen, 0);
	std::vector<byte> sbKey(Key.size() == 64 ? 32 : 16, 0);
	std::vector<uint> wK(_dfnRounds * 2 + 8, 0);

	for (unsigned int i = 0; i < k64Cnt; i++)
	{
		// round key material
		eKm[i] = IntUtils::BytesToLe32(Key, keyCtr);
		keyCtr += 4;
		oKm[i] = IntUtils::BytesToLe32(Key, keyCtr);
		keyCtr += 4;
		// sbox key material
		IntUtils::Le32ToBytes(MDSEncode(eKm[i], oKm[i]), sbKey, ((k64Cnt * 4) - 4) - (i * 4));
	}

	keyCtr = 0;

	while (keyCtr < KEY_BITS)
	{
		// create the expanded keys
		if (keyCtr < (int)(wK.size() / 2))
		{
			Q = keyCtr * SK_STEP;
			A = Mix(Q, eKm, k64Cnt);
			B = Mix(Q + SK_BUMP, oKm, k64Cnt);
			B = B << 8 | (uint)(B >> 24);
			A += B;
			wK[keyCtr * 2] = A;
			A += B;
			wK[keyCtr * 2 + 1] = A << SK_ROTL | (long)(A >> (32 - SK_ROTL));
		}

		// gen s-box members
		Y0 = Y1 = Y2 = Y3 = keyCtr;

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
		_sprBox[keyCtr * 2] = MDS0[(byte)Q0[(byte)Q0[Y0] ^ sbKey[4]] ^ sbKey[0]];
		_sprBox[keyCtr * 2 + 1] = MDS1[(byte)Q0[Q1[Y1] ^ sbKey[5]] ^ sbKey[1]];
		_sprBox[(keyCtr * 2) + 0x200] = MDS2[(byte)Q1[(byte)Q0[Y2] ^ sbKey[6]] ^ sbKey[2]];
		_sprBox[keyCtr++ * 2 + 0x201] = MDS3[(byte)Q1[(byte)Q1[Y3] ^ sbKey[7]] ^ sbKey[3]];
	}

	// expanded key
	_expKey = wK;
}

// *** Rounds Processing *** //

void TFX::Decrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	const unsigned int LRD = 8;
	unsigned int keyCtr = 4;
	uint X2 = IntUtils::BytesToLe32(Input, InOffset) ^ _expKey[keyCtr];
	uint X3 = IntUtils::BytesToLe32(Input, InOffset + 4) ^ _expKey[++keyCtr];
	uint X0 = IntUtils::BytesToLe32(Input, InOffset + 8) ^ _expKey[++keyCtr];
	uint X1 = IntUtils::BytesToLe32(Input, InOffset + 12) ^ _expKey[++keyCtr];
	uint T0, T1;
	keyCtr = _expKey.size();

	do
	{
		// round 1
		T0 = Fe0(X2);
		T1 = Fe3(X3);
		X1 ^= T0 + 2 * T1 + _expKey[--keyCtr];
		X0 = (X0 << 1 | (X0 >> 31)) ^ (T0 + T1 + _expKey[--keyCtr]);
		X1 = (X1 >> 1) | X1 << 31;
		// round 2
		T0 = Fe0(X0);
		T1 = Fe3(X1);
		X3 ^= T0 + 2 * T1 + _expKey[--keyCtr];
		X2 = (X2 << 1 | (X2 >> 31)) ^ (T0 + T1 + _expKey[--keyCtr]);
		X3 = (X3 >> 1) | X3 << 31;

	} while (keyCtr != LRD);

	keyCtr = 0;
	IntUtils::Le32ToBytes(X0 ^ _expKey[keyCtr], Output, OutOffset);
	IntUtils::Le32ToBytes(X1 ^ _expKey[++keyCtr], Output, OutOffset + 4);
	IntUtils::Le32ToBytes(X2 ^ _expKey[++keyCtr], Output, OutOffset + 8);
	IntUtils::Le32ToBytes(X3 ^ _expKey[++keyCtr], Output, OutOffset + 12);
}

void TFX::Encrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	const unsigned int LRD = _expKey.size() - 1;
	unsigned int keyCtr = 0;
	uint X0 = IntUtils::BytesToLe32(Input, InOffset) ^ _expKey[keyCtr];
	uint X1 = IntUtils::BytesToLe32(Input, InOffset + 4) ^ _expKey[++keyCtr];
	uint X2 = IntUtils::BytesToLe32(Input, InOffset + 8) ^ _expKey[++keyCtr];
	uint X3 = IntUtils::BytesToLe32(Input, InOffset + 12) ^ _expKey[++keyCtr];
	uint T0, T1;

	keyCtr = 7;
	do
	{
		T0 = Fe0(X0);
		T1 = Fe3(X1);
		X2 ^= T0 + T1 + _expKey[++keyCtr];
		X2 = (X2 >> 1) | X2 << 31;
		X3 = (X3 << 1 | (X3 >> 31)) ^ (T0 + 2 * T1 + _expKey[++keyCtr]);

		T0 = Fe0(X2);
		T1 = Fe3(X3);
		X0 ^= T0 + T1 + _expKey[++keyCtr];
		X0 = (X0 >> 1) | X0 << 31;
		X1 = (X1 << 1 | (X1 >> 31)) ^ (T0 + 2 * T1 + _expKey[++keyCtr]);

	} while (keyCtr != LRD);

	keyCtr = 4;
	IntUtils::Le32ToBytes(X2 ^ _expKey[keyCtr], Output, OutOffset);
	IntUtils::Le32ToBytes(X3 ^ _expKey[++keyCtr], Output, OutOffset + 4);
	IntUtils::Le32ToBytes(X0 ^ _expKey[++keyCtr], Output, OutOffset + 8);
	IntUtils::Le32ToBytes(X1 ^ _expKey[++keyCtr], Output, OutOffset + 12);
}

// *** Helpers *** //

uint TFX::Mix(const uint X, const std::vector<uint> &Key, const unsigned int Count)
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

uint TFX::MDSEncode(uint K0, uint K1)
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

NAMESPACE_BLOCKEND