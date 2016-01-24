#include "THX.h"
#include "Twofish.h"
#include "HKDF.h"
#include "HMAC.h"
#include "IntUtils.h"
#include "DigestFromName.h"

NAMESPACE_BLOCK

using CEX::Utility::IntUtils;

void THX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Decrypt16(Input, 0, Output, 0);
}

void THX::DecryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	Decrypt16(Input, InOffset, Output, OutOffset);
}

void THX::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_dfnRounds = 0;
		_ikmSize = 0;
		_isEncryption = false;
		_isInitialized = false;

		IntUtils::ClearVector(_expKey);
		IntUtils::ClearVector(_sprBox);
		IntUtils::ClearVector(_hkdfInfo);
		IntUtils::ClearVector(_legalKeySizes);
		IntUtils::ClearVector(_legalRounds);

		if (_kdfEngine != 0)
		{
			_kdfEngine->Destroy();
			if (_destroyEngine)
				delete _kdfEngine;
		}
	}
}

void THX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Encrypt16(Input, 0, Output, 0);
}

void THX::EncryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	Encrypt16(Input, InOffset, Output, OutOffset);
}

void THX::Initialize(bool Encryption, const KeyParams &KeyParam)
{
	int dgtsze = GetIkmSize(_kdfEngineType);
	int dgtblk = GetSaltSize(_kdfEngineType);
	const std::vector<byte> &key = KeyParam.Key();
	std::string msg = "Invalid key size! Key must be either 16, 24, 32, 64 bytes or, (length - IKm length: {" +
		IntUtils::ToString(dgtsze) + "} bytes) + multiple of {" + IntUtils::ToString(dgtblk) + "} block size.";

	if (key.size() < _legalKeySizes[0])
		throw CryptoSymmetricCipherException("THX:Initialize", msg);
	if (key.size() > _legalKeySizes[3] && (key.size() - dgtsze) % dgtblk != 0)
		throw CryptoSymmetricCipherException("THX:Initialize", msg);

	for (unsigned int i = 0; i < _legalKeySizes.size(); ++i)
	{
		if (key.size() == _legalKeySizes[i])
			break;
		if (i == _legalKeySizes.size() - 1)
			throw CryptoSymmetricCipherException("THX:Initialize", msg);
	}

	// get the kdf digest engine
	if (key.size() > MAX_STDKEY)
		_kdfEngine = GetDigest(_kdfEngineType);

	_isEncryption = Encryption;
	// expand the key
	ExpandKey(key);
	// ready to transform data
	_isInitialized = true;


	/*const std::vector<byte> &Key = KeyParam.Key();

	if (Key.size() < _legalKeySizes[0])
	{
		std::string message = "Invalid key size! Key must be at least {" + IntUtils::ToString(_legalKeySizes[0]) + "} bytes ({" + IntUtils::ToString(_legalKeySizes[0] * 8) + "} bit).";
		throw CryptoSymmetricCipherException("RHX:Initialize", message);
	}
	if ((Key.size() - _kdfEngine->DigestSize()) % _kdfEngine->BlockSize() != 0)
	{
		std::string message = "Invalid key size! Key must be (length - IKm length: {" + IntUtils::ToString(_kdfEngine->DigestSize()) + "} bytes) + multiple of {" + IntUtils::ToString(_kdfEngine->BlockSize()) + "} block size.";
		throw CryptoSymmetricCipherException("RHX:Initialize", message);
	}

	_isEncryption = Encryption;
	ExpandKey(KeyParam.Key());
	_isInitialized = true;*/
}

void THX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (_isEncryption)
		EncryptBlock(Input, Output);
	else
		DecryptBlock(Input, Output);
}

void THX::Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	if (_isEncryption)
		EncryptBlock(Input, InOffset, Output, OutOffset);
	else
		DecryptBlock(Input, InOffset, Output, OutOffset);
}

void THX::ExpandKey(const std::vector<byte> &Key)
{
	// min possible size for hkdf extended is 768 bit (96 bytes)
	if (Key.size() > MAX_STDKEY)
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
	unsigned int k64Cnt = 4;
	unsigned int keyCtr = 0;
	unsigned int keySize = _dfnRounds * 2 + 8;
	unsigned int kbtSize = keySize * 4;
	uint Y0, Y1, Y2, Y3;
	std::vector<byte> rawKey(kbtSize, 0);
	std::vector<byte> sbKey(16, 0);
	std::vector<uint> eKm(k64Cnt, 0);
	std::vector<uint> oKm(k64Cnt, 0);
	std::vector<uint> wK(keySize, 0);
	unsigned int saltSize = Key.size() - _ikmSize;

	// salt must be divisible of hash blocksize
	if (saltSize % _kdfEngine->BlockSize() != 0)
		saltSize = saltSize - saltSize % _kdfEngine->BlockSize();

	// hkdf input
	std::vector<byte> hkdfKey(_ikmSize, 0);
	std::vector<byte> hkdfSalt(saltSize, 0);

	// copy hkdf key and salt from user key
	memcpy(&hkdfKey[0], &Key[0], _ikmSize);
	memcpy(&hkdfSalt[0], &Key[_ikmSize], saltSize);

	// HKDF generator expands array
	CEX::Mac::HMAC hmac(_kdfEngine);
	CEX::Generator::HKDF gen(&hmac);
	gen.Initialize(hkdfSalt, hkdfKey, _hkdfInfo);
	gen.Generate(rawKey);

	// copy bytes to working key
	memcpy(&wK[0], &rawKey[0], kbtSize);

	for (unsigned int i = 0; i < k64Cnt; i++)
	{
		// round key material
		eKm[i] = IntUtils::BytesToLe32(rawKey, keyCtr);
		keyCtr += 4;
		oKm[i] = IntUtils::BytesToLe32(rawKey, keyCtr);
		keyCtr += 4;
		// sbox key material
		IntUtils::Le32ToBytes(MDSEncode(eKm[i], oKm[i]), sbKey, ((k64Cnt * 4) - 4) - (i * 4));
	}

	keyCtr = 0;

	while (keyCtr < KEY_BITS)
	{
		Y0 = Y1 = Y2 = Y3 = keyCtr;

		Y0 = (byte)Q1[Y0] ^ sbKey[12];
		Y1 = (byte)Q0[Y1] ^ sbKey[13];
		Y2 = (byte)Q0[Y2] ^ sbKey[14];
		Y3 = (byte)Q1[Y3] ^ sbKey[15];

		Y0 = (byte)Q1[Y0] ^ sbKey[8];
		Y1 = (byte)Q1[Y1] ^ sbKey[9];
		Y2 = (byte)Q0[Y2] ^ sbKey[10];
		Y3 = (byte)Q0[Y3] ^ sbKey[11];

		// sbox members as MDS matrix multiplies 
		_sprBox[keyCtr * 2] = MDS0[(byte)Q0[(byte)Q0[Y0] ^ sbKey[4]] ^ sbKey[0]];
		_sprBox[keyCtr * 2 + 1] = MDS1[(byte)Q0[Q1[Y1] ^ sbKey[5]] ^ sbKey[1]];
		_sprBox[keyCtr * 2 + 0x200] = MDS2[(byte)Q1[(byte)Q0[Y2] ^ sbKey[6]] ^ sbKey[2]];
		_sprBox[keyCtr++ * 2 + 0x201] = MDS3[(byte)Q1[(byte)Q1[Y3] ^ sbKey[7]] ^ sbKey[3]];
	}

	// key processed
	_expKey = wK;
}

void THX::StandardExpand(const std::vector<byte> &Key)
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
			A = Mix32(Q, eKm, k64Cnt);
			B = Mix32(Q + SK_BUMP, oKm, k64Cnt);
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

void THX::Decrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
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

void THX::Encrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
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

IDigest* THX::GetDigest(Digests DigestType)
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

int THX::GetIkmSize(Digests DigestType)
{
	switch (DigestType)
	{
	case Digests::Blake256:
	case Digests::Keccak256:
	case Digests::SHA256:
	case Digests::Skein256:
		return 32;
	case Digests::Blake512:
	case Digests::Keccak512:
	case Digests::SHA512:
	case Digests::Skein512:
		return 64;
	case Digests::Skein1024:
		return 128;
	default:
		throw CryptoSymmetricCipherException("RHX:GetDigestSize", "The digest type is not supported!");
	}
}

int THX::GetSaltSize(Digests DigestType)
{
	switch (DigestType)
	{
	case Digests::Blake256:
	case Digests::Skein256:
		return 32;
	case Digests::Blake512:
	case Digests::SHA256:
	case Digests::Skein512:
		return 64;
	case Digests::SHA512:
	case Digests::Skein1024:
		return 128;
	case Digests::Keccak256:
		return 136;
	case Digests::Keccak512:
		return 72;
	default:
		throw CryptoSymmetricCipherException("RHX:GetBlockSize", "The digest type is not supported!");
	}
}

uint THX::Mix32(const uint X, const std::vector<uint> &Key, const unsigned int Count)
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