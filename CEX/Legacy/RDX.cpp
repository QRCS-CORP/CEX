#include "RDX.h"
#include "Rijndael.h"
#include "IntUtils.h"

NAMESPACE_BLOCK

using CEX::Utility::IntUtils;

void RDX::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (_blockSize == BLOCK16)
		Decrypt16(Input, 0, Output, 0);
	else
		Decrypt32(Input, 0, Output, 0);
}

void RDX::DecryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	if (_blockSize == BLOCK16)
		Decrypt16(Input, InOffset, Output, OutOffset);
	else
		Decrypt32(Input, InOffset, Output, OutOffset);
}

void RDX::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_blockSize = 0;
		_isEncryption = false;
		_isInitialized = false;
		_NB = 0;
		_NK = 0;
		_NR = 0;

		IntUtils::ClearVector(_expKey);
		IntUtils::ClearVector(_legalKeySizes);
		IntUtils::ClearVector(_legalRounds);
	}
}

void RDX::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (_blockSize == BLOCK16)
		Encrypt16(Input, 0, Output, 0);
	else
		Encrypt32(Input, 0, Output, 0);
}

void RDX::EncryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	if (_blockSize == BLOCK16)
		Encrypt16(Input, InOffset, Output, OutOffset);
	else
		Encrypt32(Input, InOffset, Output, OutOffset);
}

void RDX::Initialize(bool Encryption, const KeyParams &KeyParam)
{
	unsigned int keyLen = KeyParam.Key().size();
	if (keyLen != 16 && keyLen != 24 && keyLen != 32 && keyLen != 64)
		throw CryptoSymmetricCipherException("RDX:Initialize", "Invalid key size! Valid sizes are 16, 24, 32, 64 bytes.");

	_isEncryption = Encryption;
	// expand the key
	ExpandKey(KeyParam.Key(), Encryption);
}

void RDX::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (_isEncryption)
		EncryptBlock(Input, Output);
	else
		DecryptBlock(Input, Output);
}

void RDX::Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	if (_isEncryption)
		EncryptBlock(Input, InOffset, Output, OutOffset);
	else
		DecryptBlock(Input, InOffset, Output, OutOffset);
}

// *** Key Schedule *** //

/// <remarks>
/// Expand the key and set state variables
/// </remarks>
void RDX::ExpandKey(const std::vector<byte> &Key, bool Encryption)
{

	// block and key in 32 bit words
	_NB = _blockSize / 4;
	_NK = (unsigned int)(Key.size() / 4);

	// rounds calculation
	if (_NK == 16)
		_NR = 22;
	else if (_NB == 8 || _NK == 8)
		_NR = 14;
	else if (_NK == 6)
		_NR = 12;
	else
		_NR = 10;

	// setup expanded key
	unsigned int keySize = _NB * (_NR + 1);
	std::vector<uint> wK(keySize, 0);

	int pos = -1;
	// add bytes to beginning of working key array
	for (unsigned int i = 0; i < _NK; i++)
	{
		uint value = (uint)(Key[++pos] << 24);
		value |= (uint)(Key[++pos] << 16);
		value |= (uint)(Key[++pos] << 8);
		value |= (uint)(Key[++pos]);
		wK[i] = value;
	}

	// build the remaining round keys
	for (unsigned int i = _NK; i < keySize; i++)
	{
		uint temp = wK[i - 1];

		// if it is a 512 bit key, maintain step 8 interval for 
		// additional processing steps, equal to a 256 bit key distribution
		if (_NK > 8)
		{
			if (i % _NK == 0 || i % _NK == 8)
			{
				// round the key
				uint rot = (uint)((temp << 8) | ((temp >> 24) & 0xff));
				// subbyte step
				temp = SubByte(rot) ^ Rcon[i / _NK];
			}
			// step ik + 4 and 12
			else if ((i % _NK) == 4 || (i % _NK) == 12)
			{
				temp = SubByte(temp);
			}
		}
		else
		{
			if (i % _NK == 0)
			{
				// round the key
				uint rot = (uint)((temp << 8) | ((temp >> 24) & 0xff));
				// subbyte step
				temp = SubByte(rot) ^ Rcon[i / _NK];
			}
			// step ik + 4
			else if (_NK > 6 && (i % _NK) == 4)
			{
				temp = SubByte(temp);
			}
		}
		// w[i-Nk] ^ w[i]
		wK[i] = (uint)(wK[i - _NK] ^ temp);
	}

	// inverse cipher
	if (!Encryption)
	{
		// reverse key
		for (unsigned int i = 0, k = keySize - _NB; i < k; i += _NB, k -= _NB)
		{
			for (unsigned int j = 0; j < _NB; j++)
			{
				uint temp = wK[i + j];
				wK[i + j] = wK[k + j];
				wK[k + j] = temp;
			}
		}
		// sbox inversion
		for (unsigned int i = _NB; i < keySize - _NB; i++)
		{
			wK[i] = IT0[SBox[(byte)(wK[i] >> 24)]] ^
				IT1[SBox[(byte)(wK[i] >> 16)]] ^
				IT2[SBox[(byte)(wK[i] >> 8)]] ^
				IT3[SBox[(byte)wK[i]]];
		}
	}

	_isInitialized = true;

	_expKey = wK;
}

// *** Rounds Processing ***

void RDX::Decrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	const unsigned int LRD = _expKey.size() - 5;
	unsigned int keyCtr = 0;

	// round 0
	uint X0 = IntUtils::BytesToBe32(Input, InOffset) ^ _expKey[keyCtr];
	uint X1 = IntUtils::BytesToBe32(Input, InOffset + 4) ^ _expKey[++keyCtr];
	uint X2 = IntUtils::BytesToBe32(Input, InOffset + 8) ^ _expKey[++keyCtr];
	uint X3 = IntUtils::BytesToBe32(Input, InOffset + 12) ^ _expKey[++keyCtr];

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

void RDX::Decrypt32(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	const unsigned int LRD = _expKey.size() - 9;
	unsigned int keyCtr = 0;

	// round 0
	uint X0 = IntUtils::BytesToBe32(Input, InOffset) ^ _expKey[keyCtr];
	uint X1 = IntUtils::BytesToBe32(Input, InOffset + 4) ^ _expKey[++keyCtr];
	uint X2 = IntUtils::BytesToBe32(Input, InOffset + 8) ^ _expKey[++keyCtr];
	uint X3 = IntUtils::BytesToBe32(Input, InOffset + 12) ^ _expKey[++keyCtr];
	uint X4 = IntUtils::BytesToBe32(Input, InOffset + 16) ^ _expKey[++keyCtr];
	uint X5 = IntUtils::BytesToBe32(Input, InOffset + 20) ^ _expKey[++keyCtr];
	uint X6 = IntUtils::BytesToBe32(Input, InOffset + 24) ^ _expKey[++keyCtr];
	uint X7 = IntUtils::BytesToBe32(Input, InOffset + 28) ^ _expKey[++keyCtr];

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

void RDX::Encrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	const unsigned int LRD = _expKey.size() - 5;
	unsigned int keyCtr = 0;

	// round 0
	uint X0 = IntUtils::BytesToBe32(Input, InOffset) ^ _expKey[keyCtr];
	uint X1 = IntUtils::BytesToBe32(Input, InOffset + 4) ^ _expKey[++keyCtr];
	uint X2 = IntUtils::BytesToBe32(Input, InOffset + 8) ^ _expKey[++keyCtr];
	uint X3 = IntUtils::BytesToBe32(Input, InOffset + 12) ^ _expKey[++keyCtr];

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

void RDX::Encrypt32(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	const unsigned int LRD = _expKey.size() - 9;
	unsigned int keyCtr = 0;

	// round 0
	uint X0 = IntUtils::BytesToBe32(Input, InOffset) ^ _expKey[keyCtr];
	uint X1 = IntUtils::BytesToBe32(Input, InOffset + 4) ^ _expKey[++keyCtr];
	uint X2 = IntUtils::BytesToBe32(Input, InOffset + 8) ^ _expKey[++keyCtr];
	uint X3 = IntUtils::BytesToBe32(Input, InOffset + 12) ^ _expKey[++keyCtr];
	uint X4 = IntUtils::BytesToBe32(Input, InOffset + 16) ^ _expKey[++keyCtr];
	uint X5 = IntUtils::BytesToBe32(Input, InOffset + 20) ^ _expKey[++keyCtr];
	uint X6 = IntUtils::BytesToBe32(Input, InOffset + 24) ^ _expKey[++keyCtr];
	uint X7 = IntUtils::BytesToBe32(Input, InOffset + 28) ^ _expKey[++keyCtr];

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

// *** Helpers *** //

uint RDX::SubByte(uint Rot)
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
