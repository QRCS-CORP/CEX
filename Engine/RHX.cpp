#include "RHX.h"
#include "Rijndael.h"
#include "HKDF.h"
#include "HMAC.h"
#include "IntUtils.h"
#include "DigestFromName.h"

NAMESPACE_BLOCK

void RHX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (_blockSize == BLOCK16)
		Decrypt16(Input, 0, Output, 0);
	else
		Decrypt32(Input, 0, Output, 0);
}

void RHX::DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (_blockSize == BLOCK16)
		Decrypt16(Input, InOffset, Output, OutOffset);
	else
		Decrypt32(Input, InOffset, Output, OutOffset);
}

void RHX::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_blockSize = 0;
		_dfnRounds = 0;
		_ikmSize = 0;
		_isEncryption = false;
		_isInitialized = false;

		CEX::Utility::IntUtils::ClearVector(_expKey);
		CEX::Utility::IntUtils::ClearVector(_hkdfInfo);
		CEX::Utility::IntUtils::ClearVector(_legalKeySizes);
		CEX::Utility::IntUtils::ClearVector(_legalRounds);

		if (_kdfEngine != 0)
		{
			_kdfEngine->Destroy();
			if (_destroyEngine)
				delete _kdfEngine;
		}
	}
}

void RHX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (_blockSize == BLOCK16)
		Encrypt16(Input, 0, Output, 0);
	else
		Encrypt32(Input, 0, Output, 0);
}

void RHX::EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (_blockSize == BLOCK16)
		Encrypt16(Input, InOffset, Output, OutOffset);
	else
		Encrypt32(Input, InOffset, Output, OutOffset);
}

void RHX::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
	int dgtsze = GetIkmSize(_kdfEngineType);
	const std::vector<byte> &key = KeyParam.Key();
	std::string msg = "Invalid key size! Key must be either 16, 24, 32, 64 bytes or, a multiple of the hkdf hash output size.";
	
	if (key.size() < _legalKeySizes[0])
		throw CryptoSymmetricCipherException("RHX:Initialize", msg);
	if (key.size() > _legalKeySizes[3] && (key.size() % dgtsze) != 0)
		throw CryptoSymmetricCipherException("RHX:Initialize", msg);

	for (size_t i = 0; i < _legalKeySizes.size(); ++i)
	{
		if (key.size() == _legalKeySizes[i])
			break;
		if (i == _legalKeySizes.size() - 1)
			throw CryptoSymmetricCipherException("RHX:Initialize", msg);
	}

	// get the kdf digest engine
	if (_kdfEngineType != CEX::Enumeration::Digests::None)
	{
		if (key.size() < _ikmSize)
			throw CryptoSymmetricCipherException("RHX:Initialize", "Invalid key! HKDF extended mode requires key be at least hash output size.");

		_kdfEngine = GetDigest(_kdfEngineType);
	}

	_isEncryption = Encryption;
	// expand the key
	ExpandKey(Encryption, key);
	// ready to transform data
	_isInitialized = true;
}

void RHX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (_isEncryption)
		EncryptBlock(Input, Output);
	else
		DecryptBlock(Input, Output);
}

void RHX::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	if (_isEncryption)
		EncryptBlock(Input, InOffset, Output, OutOffset);
	else
		DecryptBlock(Input, InOffset, Output, OutOffset);
}

// *** Key Schedule *** //

void RHX::ExpandKey(bool Encryption, const std::vector<byte> &Key)
{
	if (_kdfEngineType != CEX::Enumeration::Digests::None)
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
		size_t blkWords = _blockSize / 4;

		// reverse key
		for (size_t i = 0, k = _expKey.size() - blkWords; i < k; i += blkWords, k -= blkWords)
		{
			for (size_t j = 0; j < blkWords; j++)
			{
				uint temp = _expKey[i + j];
				_expKey[i + j] = _expKey[k + j];
				_expKey[k + j] = temp;
			}
		}
		// sbox inversion
		for (size_t i = blkWords; i < _expKey.size() - blkWords; i++)
		{
			_expKey[i] = IT0[SBox[(_expKey[i] >> 24)]] ^
				IT1[SBox[(byte)(_expKey[i] >> 16)]] ^
				IT2[SBox[(byte)(_expKey[i] >> 8)]] ^
				IT3[SBox[(byte)_expKey[i]]];
		}
	}
}

void RHX::SecureExpand(const std::vector<byte> &Key)
{
	// block and key in 32 bit words
	size_t blkWords = _blockSize / 4;
	// expanded key size
	size_t keySize = blkWords * (_dfnRounds + 1);
	// kdf return array
	size_t keyBytes = keySize * 4;
	std::vector<byte> rawKey(keyBytes, 0);
	size_t saltSize = Key.size() - _ikmSize;

	// hkdf input
	std::vector<byte> kdfKey(_ikmSize, 0);
	std::vector<byte> kdfSalt(0, 0);
	// copy hkdf key and salt from user key
	memcpy(&kdfKey[0], &Key[0], _ikmSize);
	if (saltSize > 0)
	{
		kdfSalt.resize(saltSize);
		memcpy(&kdfSalt[0], &Key[_ikmSize], saltSize);
	}

	// HKDF generator expands array 
	CEX::Mac::HMAC hmac(_kdfEngine);
	CEX::Generator::HKDF gen(&hmac);
	gen.Initialize(kdfSalt, kdfKey, _hkdfInfo);
	gen.Generate(rawKey);

	// initialize working key
	_expKey.resize(keySize, 0);
	// copy bytes to working key
	memcpy(&_expKey[0], &rawKey[0], keyBytes);
}

void RHX::StandardExpand(const std::vector<byte> &Key)
{
	// block in 32 bit words
	int blkWords = _blockSize / 4;
	// key in 32 bit words
	int keyWords = Key.size() / 4;
	// rounds calculation, 512 gets 22 rounds
	_dfnRounds = (blkWords == 8 || keyWords == 8) ? 14 : keyWords + 6;
	// setup expanded key
	_expKey.resize(blkWords * (_dfnRounds + 1), 0);

	if (keyWords == 16)
	{
		_expKey[0] = CEX::Utility::IntUtils::BytesToBe32(Key, 0);
		_expKey[1] = CEX::Utility::IntUtils::BytesToBe32(Key, 4);
		_expKey[2] = CEX::Utility::IntUtils::BytesToBe32(Key, 8);
		_expKey[3] = CEX::Utility::IntUtils::BytesToBe32(Key, 12);
		_expKey[4] = CEX::Utility::IntUtils::BytesToBe32(Key, 16);
		_expKey[5] = CEX::Utility::IntUtils::BytesToBe32(Key, 20);
		_expKey[6] = CEX::Utility::IntUtils::BytesToBe32(Key, 24);
		_expKey[7] = CEX::Utility::IntUtils::BytesToBe32(Key, 28);
		_expKey[8] = CEX::Utility::IntUtils::BytesToBe32(Key, 32);
		_expKey[9] = CEX::Utility::IntUtils::BytesToBe32(Key, 36);
		_expKey[10] = CEX::Utility::IntUtils::BytesToBe32(Key, 40);
		_expKey[11] = CEX::Utility::IntUtils::BytesToBe32(Key, 44);
		_expKey[12] = CEX::Utility::IntUtils::BytesToBe32(Key, 48);
		_expKey[13] = CEX::Utility::IntUtils::BytesToBe32(Key, 52);
		_expKey[14] = CEX::Utility::IntUtils::BytesToBe32(Key, 56);
		_expKey[15] = CEX::Utility::IntUtils::BytesToBe32(Key, 60);

		// k512 R: 16,24,32,40,48,56,64,72,80,88, S: 20,28,36,44,52,60,68,76,84
		ExpandRotBlock(_expKey, 16, 16);
		ExpandSubBlock(_expKey, 20, 16);
		ExpandRotBlock(_expKey, 24, 16);
		ExpandSubBlock(_expKey, 28, 16);
		ExpandRotBlock(_expKey, 32, 16);
		ExpandSubBlock(_expKey, 36, 16);
		ExpandRotBlock(_expKey, 40, 16);
		ExpandSubBlock(_expKey, 44, 16);
		ExpandRotBlock(_expKey, 48, 16);
		ExpandSubBlock(_expKey, 52, 16);
		ExpandRotBlock(_expKey, 56, 16);
		ExpandSubBlock(_expKey, 60, 16);
		ExpandRotBlock(_expKey, 64, 16);
		ExpandSubBlock(_expKey, 68, 16);
		ExpandRotBlock(_expKey, 72, 16);
		ExpandSubBlock(_expKey, 76, 16);
		ExpandRotBlock(_expKey, 80, 16);
		ExpandSubBlock(_expKey, 84, 16);
		ExpandRotBlock(_expKey, 88, 16);

		if (blkWords == 8)
		{
			ExpandSubBlock(_expKey, 92, 16);
			ExpandRotBlock(_expKey, 96, 16);
			ExpandSubBlock(_expKey, 100, 16);
			ExpandRotBlock(_expKey, 104, 16);
			ExpandSubBlock(_expKey, 108, 16);
			ExpandRotBlock(_expKey, 112, 16);
			ExpandSubBlock(_expKey, 116, 16);
			ExpandRotBlock(_expKey, 120, 16);
			ExpandSubBlock(_expKey, 124, 16);
			ExpandRotBlock(_expKey, 128, 16);
			ExpandSubBlock(_expKey, 132, 16);
			ExpandRotBlock(_expKey, 136, 16);
			ExpandSubBlock(_expKey, 140, 16);
			ExpandRotBlock(_expKey, 144, 16);
			ExpandSubBlock(_expKey, 148, 16);
			ExpandRotBlock(_expKey, 152, 16);
			ExpandSubBlock(_expKey, 156, 16);
			ExpandRotBlock(_expKey, 160, 16);
			ExpandSubBlock(_expKey, 164, 16);
			ExpandRotBlock(_expKey, 168, 16);
			ExpandSubBlock(_expKey, 172, 16);
		}
	}
	else if (keyWords == 8)
	{
		_expKey[0] = CEX::Utility::IntUtils::BytesToBe32(Key, 0);
		_expKey[1] = CEX::Utility::IntUtils::BytesToBe32(Key, 4);
		_expKey[2] = CEX::Utility::IntUtils::BytesToBe32(Key, 8);
		_expKey[3] = CEX::Utility::IntUtils::BytesToBe32(Key, 12);
		_expKey[4] = CEX::Utility::IntUtils::BytesToBe32(Key, 16);
		_expKey[5] = CEX::Utility::IntUtils::BytesToBe32(Key, 20);
		_expKey[6] = CEX::Utility::IntUtils::BytesToBe32(Key, 24);
		_expKey[7] = CEX::Utility::IntUtils::BytesToBe32(Key, 28);

		// k256 R: 8,16,24,32,40,48,56 S: 12,20,28,36,44,52
		ExpandRotBlock(_expKey, 8, 8);
		ExpandSubBlock(_expKey, 12, 8);
		ExpandRotBlock(_expKey, 16, 8);
		ExpandSubBlock(_expKey, 20, 8);
		ExpandRotBlock(_expKey, 24, 8);
		ExpandSubBlock(_expKey, 28, 8);
		ExpandRotBlock(_expKey, 32, 8);
		ExpandSubBlock(_expKey, 36, 8);
		ExpandRotBlock(_expKey, 40, 8);
		ExpandSubBlock(_expKey, 44, 8);
		ExpandRotBlock(_expKey, 48, 8);
		ExpandSubBlock(_expKey, 52, 8);
		ExpandRotBlock(_expKey, 56, 8);

		if (blkWords == 8)
		{
			ExpandSubBlock(_expKey, 60, 8);
			ExpandRotBlock(_expKey, 64, 8);
			ExpandSubBlock(_expKey, 68, 8);
			ExpandRotBlock(_expKey, 72, 8);
			ExpandSubBlock(_expKey, 76, 8);
			ExpandRotBlock(_expKey, 80, 8);
			ExpandSubBlock(_expKey, 84, 8);
			ExpandRotBlock(_expKey, 88, 8);
			ExpandSubBlock(_expKey, 92, 8);
			ExpandRotBlock(_expKey, 96, 8);
			ExpandSubBlock(_expKey, 100, 8);
			ExpandRotBlock(_expKey, 104, 8);
			ExpandSubBlock(_expKey, 108, 8);
			ExpandRotBlock(_expKey, 112, 8);
			ExpandSubBlock(_expKey, 116, 8);
		}
	}
	else if (keyWords == 6)
	{
		_expKey[0] = CEX::Utility::IntUtils::BytesToBe32(Key, 0);
		_expKey[1] = CEX::Utility::IntUtils::BytesToBe32(Key, 4);
		_expKey[2] = CEX::Utility::IntUtils::BytesToBe32(Key, 8);
		_expKey[3] = CEX::Utility::IntUtils::BytesToBe32(Key, 12);
		_expKey[4] = CEX::Utility::IntUtils::BytesToBe32(Key, 16);
		_expKey[5] = CEX::Utility::IntUtils::BytesToBe32(Key, 20);

		// // k192 R: 6,12,18,24,30,36,42,48
		ExpandRotBlock(_expKey, 6, 6);
		_expKey[10] = _expKey[4] ^ _expKey[9];
		_expKey[11] = _expKey[5] ^ _expKey[10];
		ExpandRotBlock(_expKey, 12, 6);
		_expKey[16] = _expKey[10] ^ _expKey[15];
		_expKey[17] = _expKey[11] ^ _expKey[16];
		ExpandRotBlock(_expKey, 18, 6);
		_expKey[22] = _expKey[16] ^ _expKey[21];
		_expKey[23] = _expKey[17] ^ _expKey[22];
		ExpandRotBlock(_expKey, 24, 6);
		_expKey[28] = _expKey[22] ^ _expKey[27];
		_expKey[29] = _expKey[23] ^ _expKey[28];
		ExpandRotBlock(_expKey, 30, 6);
		_expKey[34] = _expKey[28] ^ _expKey[33];
		_expKey[35] = _expKey[29] ^ _expKey[34];
		ExpandRotBlock(_expKey, 36, 6);
		_expKey[40] = _expKey[34] ^ _expKey[39];
		_expKey[41] = _expKey[35] ^ _expKey[40];
		ExpandRotBlock(_expKey, 42, 6);
		_expKey[46] = _expKey[40] ^ _expKey[45];
		_expKey[47] = _expKey[41] ^ _expKey[46];
		ExpandRotBlock(_expKey, 48, 6);

		if (blkWords == 8)
		{
			_expKey[52] = _expKey[46] ^ _expKey[51];
			_expKey[53] = _expKey[47] ^ _expKey[52];
			ExpandRotBlock(_expKey, 54, 6);
			_expKey[58] = _expKey[52] ^ _expKey[57];
			_expKey[59] = _expKey[53] ^ _expKey[58];
			ExpandRotBlock(_expKey, 60, 6);
			_expKey[64] = _expKey[58] ^ _expKey[63];
			_expKey[65] = _expKey[59] ^ _expKey[64];
			ExpandRotBlock(_expKey, 66, 6);
			_expKey[70] = _expKey[64] ^ _expKey[69];
			_expKey[71] = _expKey[65] ^ _expKey[70];
			ExpandRotBlock(_expKey, 72, 6);
			_expKey[76] = _expKey[70] ^ _expKey[75];
			_expKey[77] = _expKey[71] ^ _expKey[76];
			ExpandRotBlock(_expKey, 78, 6);
			_expKey[82] = _expKey[76] ^ _expKey[81];
			_expKey[83] = _expKey[77] ^ _expKey[82];
			ExpandRotBlock(_expKey, 84, 6);
			_expKey[88] = _expKey[82] ^ _expKey[87];
			_expKey[89] = _expKey[83] ^ _expKey[88];
			ExpandRotBlock(_expKey, 90, 6);
			_expKey[94] = _expKey[88] ^ _expKey[93];
			_expKey[95] = _expKey[89] ^ _expKey[94];
			ExpandRotBlock(_expKey, 96, 6);
			_expKey[100] = _expKey[94] ^ _expKey[99];
			_expKey[101] = _expKey[95] ^ _expKey[100];
			ExpandRotBlock(_expKey, 102, 6);
			_expKey[106] = _expKey[100] ^ _expKey[105];
			_expKey[107] = _expKey[101] ^ _expKey[106];
			ExpandRotBlock(_expKey, 108, 6);
			_expKey[112] = _expKey[106] ^ _expKey[111];
			_expKey[113] = _expKey[107] ^ _expKey[112];
			ExpandRotBlock(_expKey, 114, 6);
			_expKey[118] = _expKey[112] ^ _expKey[117];
			_expKey[119] = _expKey[113] ^ _expKey[118];
		}
	}
	else
	{
		_expKey[0] = CEX::Utility::IntUtils::BytesToBe32(Key, 0);
		_expKey[1] = CEX::Utility::IntUtils::BytesToBe32(Key, 4);
		_expKey[2] = CEX::Utility::IntUtils::BytesToBe32(Key, 8);
		_expKey[3] = CEX::Utility::IntUtils::BytesToBe32(Key, 12);

		// k128 R: 4,8,12,16,20,24,28,32,36,40
		ExpandRotBlock(_expKey, 4, 4);
		ExpandRotBlock(_expKey, 8, 4);
		ExpandRotBlock(_expKey, 12, 4);
		ExpandRotBlock(_expKey, 16, 4);
		ExpandRotBlock(_expKey, 20, 4);
		ExpandRotBlock(_expKey, 24, 4);
		ExpandRotBlock(_expKey, 28, 4);
		ExpandRotBlock(_expKey, 32, 4);
		ExpandRotBlock(_expKey, 36, 4);
		ExpandRotBlock(_expKey, 40, 4);

		if (blkWords == 8)
		{
			ExpandRotBlock(_expKey, 44, 4);
			ExpandRotBlock(_expKey, 48, 4);
			ExpandRotBlock(_expKey, 52, 4);
			ExpandRotBlock(_expKey, 56, 4);
			ExpandRotBlock(_expKey, 60, 4);
			ExpandRotBlock(_expKey, 64, 4);
			ExpandRotBlock(_expKey, 68, 4);
			ExpandRotBlock(_expKey, 72, 4);
			ExpandRotBlock(_expKey, 76, 4);
			ExpandRotBlock(_expKey, 80, 4);
			ExpandRotBlock(_expKey, 84, 4);
			ExpandRotBlock(_expKey, 88, 4);
			ExpandRotBlock(_expKey, 92, 4);
			ExpandRotBlock(_expKey, 96, 4);
			ExpandRotBlock(_expKey, 100, 4);
			ExpandRotBlock(_expKey, 104, 4);
			ExpandRotBlock(_expKey, 108, 4);
			ExpandRotBlock(_expKey, 112, 4);
			ExpandRotBlock(_expKey, 116, 4);
		}
	}
}

void RHX::ExpandRotBlock(std::vector<uint> &Key, int Index, int Offset)
{
	int sub = Index - Offset;

	Key[Index] = Key[sub] ^ SubByte((Key[Index - 1] << 8) | ((Key[Index - 1] >> 24) & 0xFF)) ^ Rcon[(Index / Offset)];
	// note: you can insert noise before each mix to further equalize timing, i.e: uint tmp = SubByte(Key[Index - 1]);
	Key[++Index] = Key[++sub] ^ Key[Index - 1];
	Key[++Index] = Key[++sub] ^ Key[Index - 1];
	Key[++Index] = Key[++sub] ^ Key[Index - 1];
}

void RHX::ExpandSubBlock(std::vector<uint> &Key, int Index, int Offset)
{
	int sub = Index - Offset;

	Key[Index] = SubByte(Key[Index - 1]) ^ Key[sub];
	Key[++Index] = Key[++sub] ^ Key[Index - 1];
	Key[++Index] = Key[++sub] ^ Key[Index - 1];
	Key[++Index] = Key[++sub] ^ Key[Index - 1];
}

// *** Rounds Processing *** //

void RHX::Encrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = _expKey.size() - 5;
	size_t keyCtr = 0;

	// round 0
	uint X0 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset) ^ _expKey[keyCtr];
	uint X1 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 4) ^ _expKey[++keyCtr];
	uint X2 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 8) ^ _expKey[++keyCtr];
	uint X3 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 12) ^ _expKey[++keyCtr];

	// round 1
	uint Y0 = T0[(byte)(X0 >> 24)] ^ T1[(byte)(X1 >> 16)] ^ T2[(byte)(X2 >> 8)] ^ T3[(byte)X3] ^ _expKey[++keyCtr];
	uint Y1 = T0[(byte)(X1 >> 24)] ^ T1[(byte)(X2 >> 16)] ^ T2[(byte)(X3 >> 8)] ^ T3[(byte)X0] ^ _expKey[++keyCtr];
	uint Y2 = T0[(byte)(X2 >> 24)] ^ T1[(byte)(X3 >> 16)] ^ T2[(byte)(X0 >> 8)] ^ T3[(byte)X1] ^ _expKey[++keyCtr];
	uint Y3 = T0[(byte)(X3 >> 24)] ^ T1[(byte)(X0 >> 16)] ^ T2[(byte)(X1 >> 8)] ^ T3[(byte)X2] ^ _expKey[++keyCtr];

	while (keyCtr != LRD)
	{
		X0 = T0[(byte)(Y0 >> 24)] ^ T1[(byte)(Y1 >> 16)] ^ T2[(byte)(Y2 >> 8)] ^ T3[(byte)Y3] ^ _expKey[++keyCtr];
		X1 = T0[(byte)(Y1 >> 24)] ^ T1[(byte)(Y2 >> 16)] ^ T2[(byte)(Y3 >> 8)] ^ T3[(byte)Y0] ^ _expKey[++keyCtr];
		X2 = T0[(byte)(Y2 >> 24)] ^ T1[(byte)(Y3 >> 16)] ^ T2[(byte)(Y0 >> 8)] ^ T3[(byte)Y1] ^ _expKey[++keyCtr];
		X3 = T0[(byte)(Y3 >> 24)] ^ T1[(byte)(Y0 >> 16)] ^ T2[(byte)(Y1 >> 8)] ^ T3[(byte)Y2] ^ _expKey[++keyCtr];
		Y0 = T0[(byte)(X0 >> 24)] ^ T1[(byte)(X1 >> 16)] ^ T2[(byte)(X2 >> 8)] ^ T3[(byte)X3] ^ _expKey[++keyCtr];
		Y1 = T0[(byte)(X1 >> 24)] ^ T1[(byte)(X2 >> 16)] ^ T2[(byte)(X3 >> 8)] ^ T3[(byte)X0] ^ _expKey[++keyCtr];
		Y2 = T0[(byte)(X2 >> 24)] ^ T1[(byte)(X3 >> 16)] ^ T2[(byte)(X0 >> 8)] ^ T3[(byte)X1] ^ _expKey[++keyCtr];
		Y3 = T0[(byte)(X3 >> 24)] ^ T1[(byte)(X0 >> 16)] ^ T2[(byte)(X1 >> 8)] ^ T3[(byte)X2] ^ _expKey[++keyCtr];
	}

	// final round
	Output[OutOffset] = (byte)(SBox[(byte)(Y0 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 1] = (byte)(SBox[(byte)(Y1 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 2] = (byte)(SBox[(byte)(Y2 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 3] = (byte)(SBox[(byte)Y3] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 4] = (byte)(SBox[(byte)(Y1 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 5] = (byte)(SBox[(byte)(Y2 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 6] = (byte)(SBox[(byte)(Y3 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 7] = (byte)(SBox[(byte)Y0] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 8] = (byte)(SBox[(byte)(Y2 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 9] = (byte)(SBox[(byte)(Y3 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 10] = (byte)(SBox[(byte)(Y0 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 11] = (byte)(SBox[(byte)Y1] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 12] = (byte)(SBox[(byte)(Y3 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 13] = (byte)(SBox[(byte)(Y0 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 14] = (byte)(SBox[(byte)(Y1 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 15] = (byte)(SBox[(byte)Y2] ^ (byte)_expKey[keyCtr]);
}

void RHX::Encrypt32(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = _expKey.size() - 9;
	size_t keyCtr = 0;

	// round 0
	uint X0 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset) ^ _expKey[keyCtr];
	uint X1 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 4) ^ _expKey[++keyCtr];
	uint X2 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 8) ^ _expKey[++keyCtr];
	uint X3 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 12) ^ _expKey[++keyCtr];
	uint X4 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 16) ^ _expKey[++keyCtr];
	uint X5 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 20) ^ _expKey[++keyCtr];
	uint X6 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 24) ^ _expKey[++keyCtr];
	uint X7 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 28) ^ _expKey[++keyCtr];

	// round 1
	uint Y0 = T0[(byte)(X0 >> 24)] ^ T1[(byte)(X1 >> 16)] ^ T2[(byte)(X3 >> 8)] ^ T3[(byte)X4] ^ _expKey[++keyCtr];
	uint Y1 = T0[(byte)(X1 >> 24)] ^ T1[(byte)(X2 >> 16)] ^ T2[(byte)(X4 >> 8)] ^ T3[(byte)X5] ^ _expKey[++keyCtr];
	uint Y2 = T0[(byte)(X2 >> 24)] ^ T1[(byte)(X3 >> 16)] ^ T2[(byte)(X5 >> 8)] ^ T3[(byte)X6] ^ _expKey[++keyCtr];
	uint Y3 = T0[(byte)(X3 >> 24)] ^ T1[(byte)(X4 >> 16)] ^ T2[(byte)(X6 >> 8)] ^ T3[(byte)X7] ^ _expKey[++keyCtr];
	uint Y4 = T0[(byte)(X4 >> 24)] ^ T1[(byte)(X5 >> 16)] ^ T2[(byte)(X7 >> 8)] ^ T3[(byte)X0] ^ _expKey[++keyCtr];
	uint Y5 = T0[(byte)(X5 >> 24)] ^ T1[(byte)(X6 >> 16)] ^ T2[(byte)(X0 >> 8)] ^ T3[(byte)X1] ^ _expKey[++keyCtr];
	uint Y6 = T0[(byte)(X6 >> 24)] ^ T1[(byte)(X7 >> 16)] ^ T2[(byte)(X1 >> 8)] ^ T3[(byte)X2] ^ _expKey[++keyCtr];
	uint Y7 = T0[(byte)(X7 >> 24)] ^ T1[(byte)(X0 >> 16)] ^ T2[(byte)(X2 >> 8)] ^ T3[(byte)X3] ^ _expKey[++keyCtr];

	// rounds loop
	while (keyCtr != LRD)
	{
		X0 = T0[(byte)(Y0 >> 24)] ^ T1[(byte)(Y1 >> 16)] ^ T2[(byte)(Y3 >> 8)] ^ T3[(byte)Y4] ^ _expKey[++keyCtr];
		X1 = T0[(byte)(Y1 >> 24)] ^ T1[(byte)(Y2 >> 16)] ^ T2[(byte)(Y4 >> 8)] ^ T3[(byte)Y5] ^ _expKey[++keyCtr];
		X2 = T0[(byte)(Y2 >> 24)] ^ T1[(byte)(Y3 >> 16)] ^ T2[(byte)(Y5 >> 8)] ^ T3[(byte)Y6] ^ _expKey[++keyCtr];
		X3 = T0[(byte)(Y3 >> 24)] ^ T1[(byte)(Y4 >> 16)] ^ T2[(byte)(Y6 >> 8)] ^ T3[(byte)Y7] ^ _expKey[++keyCtr];
		X4 = T0[(byte)(Y4 >> 24)] ^ T1[(byte)(Y5 >> 16)] ^ T2[(byte)(Y7 >> 8)] ^ T3[(byte)Y0] ^ _expKey[++keyCtr];
		X5 = T0[(byte)(Y5 >> 24)] ^ T1[(byte)(Y6 >> 16)] ^ T2[(byte)(Y0 >> 8)] ^ T3[(byte)Y1] ^ _expKey[++keyCtr];
		X6 = T0[(byte)(Y6 >> 24)] ^ T1[(byte)(Y7 >> 16)] ^ T2[(byte)(Y1 >> 8)] ^ T3[(byte)Y2] ^ _expKey[++keyCtr];
		X7 = T0[(byte)(Y7 >> 24)] ^ T1[(byte)(Y0 >> 16)] ^ T2[(byte)(Y2 >> 8)] ^ T3[(byte)Y3] ^ _expKey[++keyCtr];

		Y0 = T0[(byte)(X0 >> 24)] ^ T1[(byte)(X1 >> 16)] ^ T2[(byte)(X3 >> 8)] ^ T3[(byte)X4] ^ _expKey[++keyCtr];
		Y1 = T0[(byte)(X1 >> 24)] ^ T1[(byte)(X2 >> 16)] ^ T2[(byte)(X4 >> 8)] ^ T3[(byte)X5] ^ _expKey[++keyCtr];
		Y2 = T0[(byte)(X2 >> 24)] ^ T1[(byte)(X3 >> 16)] ^ T2[(byte)(X5 >> 8)] ^ T3[(byte)X6] ^ _expKey[++keyCtr];
		Y3 = T0[(byte)(X3 >> 24)] ^ T1[(byte)(X4 >> 16)] ^ T2[(byte)(X6 >> 8)] ^ T3[(byte)X7] ^ _expKey[++keyCtr];
		Y4 = T0[(byte)(X4 >> 24)] ^ T1[(byte)(X5 >> 16)] ^ T2[(byte)(X7 >> 8)] ^ T3[(byte)X0] ^ _expKey[++keyCtr];
		Y5 = T0[(byte)(X5 >> 24)] ^ T1[(byte)(X6 >> 16)] ^ T2[(byte)(X0 >> 8)] ^ T3[(byte)X1] ^ _expKey[++keyCtr];
		Y6 = T0[(byte)(X6 >> 24)] ^ T1[(byte)(X7 >> 16)] ^ T2[(byte)(X1 >> 8)] ^ T3[(byte)X2] ^ _expKey[++keyCtr];
		Y7 = T0[(byte)(X7 >> 24)] ^ T1[(byte)(X0 >> 16)] ^ T2[(byte)(X2 >> 8)] ^ T3[(byte)X3] ^ _expKey[++keyCtr];
	}

	// final round
	Output[OutOffset] = (byte)(SBox[(byte)(Y0 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 1] = (byte)(SBox[(byte)(Y1 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 2] = (byte)(SBox[(byte)(Y3 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 3] = (byte)(SBox[(byte)Y4] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 4] = (byte)(SBox[(byte)(Y1 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 5] = (byte)(SBox[(byte)(Y2 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 6] = (byte)(SBox[(byte)(Y4 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 7] = (byte)(SBox[(byte)Y5] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 8] = (byte)(SBox[(byte)(Y2 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 9] = (byte)(SBox[(byte)(Y3 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 10] = (byte)(SBox[(byte)(Y5 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 11] = (byte)(SBox[(byte)Y6] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 12] = (byte)(SBox[(byte)(Y3 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 13] = (byte)(SBox[(byte)(Y4 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 14] = (byte)(SBox[(byte)(Y6 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 15] = (byte)(SBox[(byte)Y7] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 16] = (byte)(SBox[(byte)(Y4 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 17] = (byte)(SBox[(byte)(Y5 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 18] = (byte)(SBox[(byte)(Y7 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 19] = (byte)(SBox[(byte)Y0] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 20] = (byte)(SBox[(byte)(Y5 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 21] = (byte)(SBox[(byte)(Y6 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 22] = (byte)(SBox[(byte)(Y0 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 23] = (byte)(SBox[(byte)Y1] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 24] = (byte)(SBox[(byte)(Y6 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 25] = (byte)(SBox[(byte)(Y7 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 26] = (byte)(SBox[(byte)(Y1 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 27] = (byte)(SBox[(byte)Y2] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 28] = (byte)(SBox[(byte)(Y7 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 29] = (byte)(SBox[(byte)(Y0 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 30] = (byte)(SBox[(byte)(Y2 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 31] = (byte)(SBox[(byte)Y3] ^ (byte)_expKey[keyCtr]);
}

void RHX::Decrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = _expKey.size() - 5;
	size_t keyCtr = 0;

	// round 0
	uint X0 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset) ^ _expKey[keyCtr];
	uint X1 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 4) ^ _expKey[++keyCtr];
	uint X2 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 8) ^ _expKey[++keyCtr];
	uint X3 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 12) ^ _expKey[++keyCtr];

	// round 1
	uint Y0 = IT0[(X0 >> 24)] ^ IT1[(byte)(X3 >> 16)] ^ IT2[(byte)(X2 >> 8)] ^ IT3[(byte)X1] ^ _expKey[++keyCtr];
	uint Y1 = IT0[(X1 >> 24)] ^ IT1[(byte)(X0 >> 16)] ^ IT2[(byte)(X3 >> 8)] ^ IT3[(byte)X2] ^ _expKey[++keyCtr];
	uint Y2 = IT0[(X2 >> 24)] ^ IT1[(byte)(X1 >> 16)] ^ IT2[(byte)(X0 >> 8)] ^ IT3[(byte)X3] ^ _expKey[++keyCtr];
	uint Y3 = IT0[(X3 >> 24)] ^ IT1[(byte)(X2 >> 16)] ^ IT2[(byte)(X1 >> 8)] ^ IT3[(byte)X0] ^ _expKey[++keyCtr];

	// rounds loop
	while (keyCtr != LRD)
	{
		X0 = IT0[(Y0 >> 24)] ^ IT1[(byte)(Y3 >> 16)] ^ IT2[(byte)(Y2 >> 8)] ^ IT3[(byte)Y1] ^ _expKey[++keyCtr];
		X1 = IT0[(Y1 >> 24)] ^ IT1[(byte)(Y0 >> 16)] ^ IT2[(byte)(Y3 >> 8)] ^ IT3[(byte)Y2] ^ _expKey[++keyCtr];
		X2 = IT0[(Y2 >> 24)] ^ IT1[(byte)(Y1 >> 16)] ^ IT2[(byte)(Y0 >> 8)] ^ IT3[(byte)Y3] ^ _expKey[++keyCtr];
		X3 = IT0[(Y3 >> 24)] ^ IT1[(byte)(Y2 >> 16)] ^ IT2[(byte)(Y1 >> 8)] ^ IT3[(byte)Y0] ^ _expKey[++keyCtr];

		Y0 = IT0[(X0 >> 24)] ^ IT1[(byte)(X3 >> 16)] ^ IT2[(byte)(X2 >> 8)] ^ IT3[(byte)X1] ^ _expKey[++keyCtr];
		Y1 = IT0[(X1 >> 24)] ^ IT1[(byte)(X0 >> 16)] ^ IT2[(byte)(X3 >> 8)] ^ IT3[(byte)X2] ^ _expKey[++keyCtr];
		Y2 = IT0[(X2 >> 24)] ^ IT1[(byte)(X1 >> 16)] ^ IT2[(byte)(X0 >> 8)] ^ IT3[(byte)X3] ^ _expKey[++keyCtr];
		Y3 = IT0[(X3 >> 24)] ^ IT1[(byte)(X2 >> 16)] ^ IT2[(byte)(X1 >> 8)] ^ IT3[(byte)X0] ^ _expKey[++keyCtr];
	}

	// final round
	Output[OutOffset] = (byte)(ISBox[(byte)(Y0 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 1] = (byte)(ISBox[(byte)(Y3 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 2] = (byte)(ISBox[(byte)(Y2 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 3] = (byte)(ISBox[(byte)Y1] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 4] = (byte)(ISBox[(byte)(Y1 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 5] = (byte)(ISBox[(byte)(Y0 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 6] = (byte)(ISBox[(byte)(Y3 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 7] = (byte)(ISBox[(byte)Y2] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 8] = (byte)(ISBox[(byte)(Y2 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 9] = (byte)(ISBox[(byte)(Y1 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 10] = (byte)(ISBox[(byte)(Y0 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 11] = (byte)(ISBox[(byte)Y3] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 12] = (byte)(ISBox[(byte)(Y3 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 13] = (byte)(ISBox[(byte)(Y2 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 14] = (byte)(ISBox[(byte)(Y1 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 15] = (byte)(ISBox[(byte)Y0] ^ (byte)_expKey[keyCtr]);
}

void RHX::Decrypt32(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	const size_t LRD = _expKey.size() - 9;
	size_t keyCtr = 0;

	// round 0
	uint X0 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset) ^ _expKey[keyCtr];
	uint X1 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 4) ^ _expKey[++keyCtr];
	uint X2 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 8) ^ _expKey[++keyCtr];
	uint X3 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 12) ^ _expKey[++keyCtr];
	uint X4 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 16) ^ _expKey[++keyCtr];
	uint X5 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 20) ^ _expKey[++keyCtr];
	uint X6 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 24) ^ _expKey[++keyCtr];
	uint X7 = CEX::Utility::IntUtils::BytesToBe32(Input, InOffset + 28) ^ _expKey[++keyCtr];

	// round 1
	uint Y0 = IT0[(byte)(X0 >> 24)] ^ IT1[(byte)(X7 >> 16)] ^ IT2[(byte)(X5 >> 8)] ^ IT3[(byte)X4] ^ _expKey[++keyCtr];
	uint Y1 = IT0[(byte)(X1 >> 24)] ^ IT1[(byte)(X0 >> 16)] ^ IT2[(byte)(X6 >> 8)] ^ IT3[(byte)X5] ^ _expKey[++keyCtr];
	uint Y2 = IT0[(byte)(X2 >> 24)] ^ IT1[(byte)(X1 >> 16)] ^ IT2[(byte)(X7 >> 8)] ^ IT3[(byte)X6] ^ _expKey[++keyCtr];
	uint Y3 = IT0[(byte)(X3 >> 24)] ^ IT1[(byte)(X2 >> 16)] ^ IT2[(byte)(X0 >> 8)] ^ IT3[(byte)X7] ^ _expKey[++keyCtr];
	uint Y4 = IT0[(byte)(X4 >> 24)] ^ IT1[(byte)(X3 >> 16)] ^ IT2[(byte)(X1 >> 8)] ^ IT3[(byte)X0] ^ _expKey[++keyCtr];
	uint Y5 = IT0[(byte)(X5 >> 24)] ^ IT1[(byte)(X4 >> 16)] ^ IT2[(byte)(X2 >> 8)] ^ IT3[(byte)X1] ^ _expKey[++keyCtr];
	uint Y6 = IT0[(byte)(X6 >> 24)] ^ IT1[(byte)(X5 >> 16)] ^ IT2[(byte)(X3 >> 8)] ^ IT3[(byte)X2] ^ _expKey[++keyCtr];
	uint Y7 = IT0[(byte)(X7 >> 24)] ^ IT1[(byte)(X6 >> 16)] ^ IT2[(byte)(X4 >> 8)] ^ IT3[(byte)X3] ^ _expKey[++keyCtr];

	// rounds loop
	while (keyCtr != LRD)
	{
		X0 = IT0[(byte)(Y0 >> 24)] ^ IT1[(byte)(Y7 >> 16)] ^ IT2[(byte)(Y5 >> 8)] ^ IT3[(byte)Y4] ^ _expKey[++keyCtr];
		X1 = IT0[(byte)(Y1 >> 24)] ^ IT1[(byte)(Y0 >> 16)] ^ IT2[(byte)(Y6 >> 8)] ^ IT3[(byte)Y5] ^ _expKey[++keyCtr];
		X2 = IT0[(byte)(Y2 >> 24)] ^ IT1[(byte)(Y1 >> 16)] ^ IT2[(byte)(Y7 >> 8)] ^ IT3[(byte)Y6] ^ _expKey[++keyCtr];
		X3 = IT0[(byte)(Y3 >> 24)] ^ IT1[(byte)(Y2 >> 16)] ^ IT2[(byte)(Y0 >> 8)] ^ IT3[(byte)Y7] ^ _expKey[++keyCtr];
		X4 = IT0[(byte)(Y4 >> 24)] ^ IT1[(byte)(Y3 >> 16)] ^ IT2[(byte)(Y1 >> 8)] ^ IT3[(byte)Y0] ^ _expKey[++keyCtr];
		X5 = IT0[(byte)(Y5 >> 24)] ^ IT1[(byte)(Y4 >> 16)] ^ IT2[(byte)(Y2 >> 8)] ^ IT3[(byte)Y1] ^ _expKey[++keyCtr];
		X6 = IT0[(byte)(Y6 >> 24)] ^ IT1[(byte)(Y5 >> 16)] ^ IT2[(byte)(Y3 >> 8)] ^ IT3[(byte)Y2] ^ _expKey[++keyCtr];
		X7 = IT0[(byte)(Y7 >> 24)] ^ IT1[(byte)(Y6 >> 16)] ^ IT2[(byte)(Y4 >> 8)] ^ IT3[(byte)Y3] ^ _expKey[++keyCtr];

		Y0 = IT0[(byte)(X0 >> 24)] ^ IT1[(byte)(X7 >> 16)] ^ IT2[(byte)(X5 >> 8)] ^ IT3[(byte)X4] ^ _expKey[++keyCtr];
		Y1 = IT0[(byte)(X1 >> 24)] ^ IT1[(byte)(X0 >> 16)] ^ IT2[(byte)(X6 >> 8)] ^ IT3[(byte)X5] ^ _expKey[++keyCtr];
		Y2 = IT0[(byte)(X2 >> 24)] ^ IT1[(byte)(X1 >> 16)] ^ IT2[(byte)(X7 >> 8)] ^ IT3[(byte)X6] ^ _expKey[++keyCtr];
		Y3 = IT0[(byte)(X3 >> 24)] ^ IT1[(byte)(X2 >> 16)] ^ IT2[(byte)(X0 >> 8)] ^ IT3[(byte)X7] ^ _expKey[++keyCtr];
		Y4 = IT0[(byte)(X4 >> 24)] ^ IT1[(byte)(X3 >> 16)] ^ IT2[(byte)(X1 >> 8)] ^ IT3[(byte)X0] ^ _expKey[++keyCtr];
		Y5 = IT0[(byte)(X5 >> 24)] ^ IT1[(byte)(X4 >> 16)] ^ IT2[(byte)(X2 >> 8)] ^ IT3[(byte)X1] ^ _expKey[++keyCtr];
		Y6 = IT0[(byte)(X6 >> 24)] ^ IT1[(byte)(X5 >> 16)] ^ IT2[(byte)(X3 >> 8)] ^ IT3[(byte)X2] ^ _expKey[++keyCtr];
		Y7 = IT0[(byte)(X7 >> 24)] ^ IT1[(byte)(X6 >> 16)] ^ IT2[(byte)(X4 >> 8)] ^ IT3[(byte)X3] ^ _expKey[++keyCtr];
	}

	// final round
	Output[OutOffset] = (byte)(ISBox[(byte)(Y0 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 1] = (byte)(ISBox[(byte)(Y7 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 2] = (byte)(ISBox[(byte)(Y5 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 3] = (byte)(ISBox[(byte)Y4] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 4] = (byte)(ISBox[(byte)(Y1 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 5] = (byte)(ISBox[(byte)(Y0 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 6] = (byte)(ISBox[(byte)(Y6 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 7] = (byte)(ISBox[(byte)Y5] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 8] = (byte)(ISBox[(byte)(Y2 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 9] = (byte)(ISBox[(byte)(Y1 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 10] = (byte)(ISBox[(byte)(Y7 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 11] = (byte)(ISBox[(byte)Y6] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 12] = (byte)(ISBox[(byte)(Y3 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 13] = (byte)(ISBox[(byte)(Y2 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 14] = (byte)(ISBox[(byte)(Y0 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 15] = (byte)(ISBox[(byte)Y7] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 16] = (byte)(ISBox[(byte)(Y4 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 17] = (byte)(ISBox[(byte)(Y3 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 18] = (byte)(ISBox[(byte)(Y1 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 19] = (byte)(ISBox[(byte)Y0] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 20] = (byte)(ISBox[(byte)(Y5 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 21] = (byte)(ISBox[(byte)(Y4 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 22] = (byte)(ISBox[(byte)(Y2 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 23] = (byte)(ISBox[(byte)Y1] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 24] = (byte)(ISBox[(byte)(Y6 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 25] = (byte)(ISBox[(byte)(Y5 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 26] = (byte)(ISBox[(byte)(Y3 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 27] = (byte)(ISBox[(byte)Y2] ^ (byte)_expKey[keyCtr]);

	Output[OutOffset + 28] = (byte)(ISBox[(byte)(Y7 >> 24)] ^ (byte)(_expKey[++keyCtr] >> 24));
	Output[OutOffset + 29] = (byte)(ISBox[(byte)(Y6 >> 16)] ^ (byte)(_expKey[keyCtr] >> 16));
	Output[OutOffset + 30] = (byte)(ISBox[(byte)(Y4 >> 8)] ^ (byte)(_expKey[keyCtr] >> 8));
	Output[OutOffset + 31] = (byte)(ISBox[(byte)Y3] ^ (byte)_expKey[keyCtr]);
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
		throw CryptoSymmetricCipherException("CipherStream:KdfEngine", "The digest could not be instantiated!");
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