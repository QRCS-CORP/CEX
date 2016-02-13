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
	int dgtblk = GetSaltSize(_kdfEngineType);
	const std::vector<byte> &key = KeyParam.Key();
	std::string msg = "Invalid key size! Key must be either 16, 24, 32, 64 bytes or, (length - IKm length: {" + 
		CEX::Utility::IntUtils::ToString(dgtsze) + "} bytes) + multiple of {" + CEX::Utility::IntUtils::ToString(dgtblk) + "} block size.";
	
	if (key.size() < _legalKeySizes[0])
		throw CryptoSymmetricCipherException("RHX:Initialize", msg);
	if (key.size() > _legalKeySizes[3] && (key.size() - dgtsze) % dgtblk != 0)
		throw CryptoSymmetricCipherException("RHX:Initialize", msg);

	for (size_t i = 0; i < _legalKeySizes.size(); ++i)
	{
		if (key.size() == _legalKeySizes[i])
			break;
		if (i == _legalKeySizes.size() - 1)
			throw CryptoSymmetricCipherException("RHX:Initialize", msg);
	}

	// get the kdf digest engine
	if (key.size() > MAX_STDKEY)
		_kdfEngine = GetDigest(_kdfEngineType);

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

	// block in 32 bit words
	size_t blkWords = _blockSize / 4;
	size_t expSize = blkWords * (_dfnRounds + 1);

	// inverse cipher
	if (!Encryption)
	{
		// reverse key
		for (size_t i = 0, k = expSize - blkWords; i < k; i += blkWords, k -= blkWords)
		{
			for (size_t j = 0; j < blkWords; j++)
			{
				uint temp = _expKey[i + j];
				_expKey[i + j] = _expKey[k + j];
				_expKey[k + j] = temp;
			}
		}
		// sbox inversion
		for (size_t i = blkWords; i < expSize - blkWords; i++)
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

	// salt must be divisible of hash blocksize
	if (saltSize % _kdfEngine->BlockSize() != 0)
		saltSize = saltSize - saltSize % _kdfEngine->BlockSize();

	// hkdf input
	std::vector<byte> kdfKey(_ikmSize, 0);
	std::vector<byte> kdfSalt(saltSize, 0);
	// copy hkdf key and salt from user key
	memcpy(&kdfKey[0], &Key[0], _ikmSize);
	memcpy(&kdfSalt[0], &Key[_ikmSize], saltSize);

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
	// block and key in 32 bit words
	size_t blkWords = _blockSize / 4;
	size_t keyWords = (uint)(Key.size() / 4);

	// rounds calculation
	if (keyWords == 16)
		_dfnRounds = 22;
	else if (blkWords == 8 || keyWords == 8)
		_dfnRounds = 14;
	else if (keyWords == 6)
		_dfnRounds = 12;
	else
		_dfnRounds = 10;

	// setup expanded key
	size_t keySize = blkWords * (_dfnRounds + 1);
	_expKey.resize(keySize, 0);

	int pos = -1;
	// add bytes to beginning of working key array
	for (size_t i = 0; i < keyWords; i++)
	{
		uint value = (uint)(Key[++pos] << 24);
		value |= (uint)(Key[++pos] << 16);
		value |= (uint)(Key[++pos] << 8);
		value |= (uint)(Key[++pos]);
		_expKey[i] = value;
	}

	// build the remaining round keys
	for (size_t i = keyWords; i < keySize; i++)
	{
		uint temp = _expKey[i - 1];

		// if it is a 512 bit key, maintain step 8 interval for 
		// additional processing steps, equal to a 256 bit key distribution
		if (keyWords > 8)
		{
			if (i % keyWords == 0 || i % keyWords == 8)
			{
				// round the key
				uint rot = (uint)((temp << 8) | ((temp >> 24) & 0xff));
				// subbyte step
				temp = SubByte(rot) ^ Rcon[i / keyWords];
			}
			// step ik + 4 and 12
			else if ((i % keyWords) == 4 || (i % keyWords) == 12)
			{
				temp = SubByte(temp);
			}
		}
		else
		{
			if (i % keyWords == 0)
			{
				// round the key
				uint rot = (uint)((temp << 8) | ((temp >> 24) & 0xff));
				// subbyte step
				temp = SubByte(rot) ^ Rcon[i / keyWords];
			}
			// step ik + 4
			else if (keyWords > 6 && (i % keyWords) == 4)
			{
				temp = SubByte(temp);
			}
		}
		// w[i-Nk] ^ w[i]
		_expKey[i] = (uint)(_expKey[i - keyWords] ^ temp);
	}
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
	switch (DigestType)
	{
	case CEX::Enumeration::Digests::Blake256:
	case CEX::Enumeration::Digests::Keccak256:
	case CEX::Enumeration::Digests::SHA256:
	case CEX::Enumeration::Digests::Skein256:
		return 32;
	case CEX::Enumeration::Digests::Blake512:
	case CEX::Enumeration::Digests::Keccak512:
	case CEX::Enumeration::Digests::SHA512:
	case CEX::Enumeration::Digests::Skein512:
		return 64;
	case CEX::Enumeration::Digests::Skein1024:
		return 128;
	default:
		throw CryptoSymmetricCipherException("RHX:GetDigestSize", "The digest type is not supported!");
	}
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

int RHX::GetSaltSize(CEX::Enumeration::Digests DigestType)
{
	switch (DigestType)
	{
	case CEX::Enumeration::Digests::Blake256:
	case CEX::Enumeration::Digests::Skein256:
		return 32;
	case CEX::Enumeration::Digests::Blake512:
	case CEX::Enumeration::Digests::SHA256:
	case CEX::Enumeration::Digests::Skein512:
		return 64;
	case CEX::Enumeration::Digests::SHA512:
	case CEX::Enumeration::Digests::Skein1024:
		return 128;
	case CEX::Enumeration::Digests::Keccak256:
		return 136;
	case CEX::Enumeration::Digests::Keccak512:
		return 72;
	default:
		throw CryptoSymmetricCipherException("RHX:GetBlockSize", "The digest type is not supported!");
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