#include "Blake256.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

static constexpr uint _C32[] =
{
	0x243F6A88U, 0x85A308D3U, 0x13198A2EU, 0x03707344U,
	0xA4093822U, 0x299F31D0U, 0x082EFA98U, 0xEC4E6C89U,
	0x452821E6U, 0x38D01377U, 0xBE5466CFU, 0x34E90C6CU,
	0xC0AC29B7U, 0xC97C50DDU, 0x3F84D5B5U, 0xB5470917U
};

static constexpr uint _ftSigma[] =
{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
	11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
	7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
	9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
	2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
	12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
	13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
	6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
	10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
	11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
	7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8
};

void Blake256::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if ((InOffset + Length) > Input.size())
		throw CryptoDigestException("Blake256:BlockUpdate", "The Input buffer is too short!");

	size_t fill = 64 - _dataLen;

	// compress remaining data filled with new bits
	if (_dataLen != 0 && (Length >= fill))
	{
		memcpy(&_digestState[_dataLen], &Input[InOffset], fill);
		_T += TN_512;
		Compress32(_digestState, 0);
		InOffset += fill;
		Length -= fill;
		_dataLen = 0;
	}

	// compress data until enough for a block
	while (Length > 63)
	{
		_T += TN_512;
		Compress32(Input, InOffset);
		InOffset += 64;
		Length -= 64;
	}

	if (Length != 0)
	{
		memcpy(&_digestState[_dataLen], &Input[InOffset], Length);
		_dataLen += Length;
	}
	else
	{
		_dataLen = 0;
	}
}

void Blake256::ComputeHash(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
}

void Blake256::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_dataLen = 0;
		_isNullT = false;
		_T = 0;

		CEX::Utility::IntUtils::ClearVector(_HashVal);
		CEX::Utility::IntUtils::ClearVector(_salt32);
		CEX::Utility::IntUtils::ClearVector(_M);
		CEX::Utility::IntUtils::ClearVector(_V);
	}
}

size_t Blake256::DoFinal(std::vector<byte> &Output, const size_t OutOffset)
{
	if (Output.size() - OutOffset < DIGEST_SIZE)
		throw CryptoDigestException("Blake256:DoFinal", "The Output buffer is too short!");

	std::vector<byte> msgLen(8);
	ulong len = _T + ((uint64_t)_dataLen << 3);
	CEX::Utility::IntUtils::Be32ToBytes((uint)(len >> 32) & 0xFFFFFFFFU, msgLen, 0);
	CEX::Utility::IntUtils::Be32ToBytes((uint)(len & 0xFFFFFFFFU), msgLen, 4);

	// special case of one padding byte
	if (_dataLen == PAD_LENGTH)
	{
		_T -= 8;
		std::vector<byte> one(1, 0x81);
		BlockUpdate(one, 0, 1);
	}
	else
	{
		if (_dataLen < PAD_LENGTH)
		{
			// enough space to fill the block
			if (_dataLen == 0)
				_isNullT = true;

			_T -= TN_440 - ((uint64_t)_dataLen << 3);
			BlockUpdate(_Padding, 0, PAD_LENGTH - _dataLen);
		}
		else
		{
			// not enough space, need 2 compressions
			_T -= TN_512 - ((uint64_t)_dataLen << 3);
			BlockUpdate(_Padding, 0, 64 - _dataLen);
			_T -= TN_440;
			BlockUpdate(_Padding, 1, PAD_LENGTH);
			_isNullT = true;
		}

		std::vector<byte> one(1, 0x01);
		BlockUpdate(one, 0, 1);
		_T -= 8;
	}

	_T -= 64;
	BlockUpdate(msgLen, 0, 8);
	std::vector<byte> digest(32, 0);

	CEX::Utility::IntUtils::Be32ToBytes(_HashVal[0], digest, 0);
	CEX::Utility::IntUtils::Be32ToBytes(_HashVal[1], digest, 4);
	CEX::Utility::IntUtils::Be32ToBytes(_HashVal[2], digest, 8);
	CEX::Utility::IntUtils::Be32ToBytes(_HashVal[3], digest, 12);
	CEX::Utility::IntUtils::Be32ToBytes(_HashVal[4], digest, 16);
	CEX::Utility::IntUtils::Be32ToBytes(_HashVal[5], digest, 20);
	CEX::Utility::IntUtils::Be32ToBytes(_HashVal[6], digest, 24);
	CEX::Utility::IntUtils::Be32ToBytes(_HashVal[7], digest, 28);

	memcpy(&Output[OutOffset], &digest[0], digest.size());
	Reset();

	return Output.size();
}

void Blake256::Reset()
{
	Initialize();
}

void Blake256::Update(byte Input)
{
	std::vector<byte> one(1, Input);
	BlockUpdate(one, 0, 1);
}

// *** Protected Methods *** //

void Blake256::G32(uint A, uint B, uint C, uint D, uint R, uint I)
{
	int P = (R << 4) + I;
	int P0 = _ftSigma[P];
	int P1 = _ftSigma[P + 1];

	_V[A] += _V[B] + (_M[P0] ^ _C32[P1]);
	_V[D] = CEX::Utility::IntUtils::RotateRight(_V[D] ^ _V[A], 16);
	_V[C] += _V[D];
	_V[B] = CEX::Utility::IntUtils::RotateRight(_V[B] ^ _V[C], 12);
	_V[A] += _V[B] + (_M[P1] ^ _C32[P0]);
	_V[D] = CEX::Utility::IntUtils::RotateRight(_V[D] ^ _V[A], 8);
	_V[C] += _V[D];
	_V[B] = CEX::Utility::IntUtils::RotateRight(_V[B] ^ _V[C], 7);
}

void Blake256::Compress32(const std::vector<byte> &Block, size_t Offset)
{
	_M[0] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset);
	_M[1] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 4);
	_M[2] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 8);
	_M[3] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 12);
	_M[4] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 16);
	_M[5] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 20);
	_M[6] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 24);
	_M[7] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 28);
	_M[8] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 32);
	_M[9] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 36);
	_M[10] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 40);
	_M[11] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 44);
	_M[12] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 48);
	_M[13] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 52);
	_M[14] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 56);
	_M[15] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 60);

	_V[0] = _HashVal[0];
	_V[1] = _HashVal[1];
	_V[2] = _HashVal[2];
	_V[3] = _HashVal[3];
	_V[4] = _HashVal[4];
	_V[5] = _HashVal[5];
	_V[6] = _HashVal[6];
	_V[7] = _HashVal[7];
	_V[8] = _salt32[0] ^ 0x243F6A88U;
	_V[9] = _salt32[1] ^ 0x85A308D3U;
	_V[10] = _salt32[2] ^ 0x13198A2EU;
	_V[11] = _salt32[3] ^ 0x03707344U;
	_V[12] = 0xA4093822U;
	_V[13] = 0x299F31D0U;
	_V[14] = 0x082EFA98U;
	_V[15] = 0xEC4E6C89U;

	if (!_isNullT)
	{
		uint uLen = (uint)(_T & 0xFFFFFFFFU);
		_V[12] ^= uLen;
		_V[13] ^= uLen;
		uLen = (uint)((_T >> 32) & 0xFFFFFFFFU);
		_V[14] ^= uLen;
		_V[15] ^= uLen;
	}

	uint index = 0;
	do
	{
		G32BLK(index);
		index++;

	} while (index != ROUNDS);

	_HashVal[0] ^= _V[0];
	_HashVal[1] ^= _V[1];
	_HashVal[2] ^= _V[2];
	_HashVal[3] ^= _V[3];
	_HashVal[4] ^= _V[4];
	_HashVal[5] ^= _V[5];
	_HashVal[6] ^= _V[6];
	_HashVal[7] ^= _V[7];
	_HashVal[0] ^= _V[8];
	_HashVal[1] ^= _V[9];
	_HashVal[2] ^= _V[10];
	_HashVal[3] ^= _V[11];
	_HashVal[4] ^= _V[12];
	_HashVal[5] ^= _V[13];
	_HashVal[6] ^= _V[14];
	_HashVal[7] ^= _V[15];
	_HashVal[0] ^= _salt32[0];
	_HashVal[1] ^= _salt32[1];
	_HashVal[2] ^= _salt32[2];
	_HashVal[3] ^= _salt32[3];
	_HashVal[4] ^= _salt32[0];
	_HashVal[5] ^= _salt32[1];
	_HashVal[6] ^= _salt32[2];
	_HashVal[7] ^= _salt32[3];
}

void Blake256::G32BLK(uint Index)
{
	G32(0, 4, 8, 12, Index, 0);
	G32(1, 5, 9, 13, Index, 2);
	G32(2, 6, 10, 14, Index, 4);
	G32(3, 7, 11, 15, Index, 6);
	G32(3, 4, 9, 14, Index, 14);
	G32(2, 7, 8, 13, Index, 12);
	G32(0, 5, 10, 15, Index, 8);
	G32(1, 6, 11, 12, Index, 10);
}

void Blake256::Initialize()
{
	_HashVal =
	{
		0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
		0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
	};

	std::fill(_salt32.begin(), _salt32.end(), 0);
	_T = 0;
	_dataLen = 0;
	_isNullT = false;
	std::fill(_digestState.begin(), _digestState.end(), 0);
}

NAMESPACE_DIGESTEND