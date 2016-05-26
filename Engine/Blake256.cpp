#include "Blake256.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

static constexpr uint m_C32[] =
{
	0x243F6A88U, 0x85A308D3U, 0x13198A2EU, 0x03707344U,
	0xA4093822U, 0x299F31D0U, 0x082EFA98U, 0xEC4E6C89U,
	0x452821E6U, 0x38D01377U, 0xBE5466CFU, 0x34E90C6CU,
	0xC0AC29B7U, 0xC97C50DDU, 0x3F84D5B5U, 0xB5470917U
};

static constexpr uint m_ftSigma[] =
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

	size_t fill = 64 - m_dataLen;

	// compress remaining data filled with new bits
	if (m_dataLen != 0 && (Length >= fill))
	{
		memcpy(&m_digestState[m_dataLen], &Input[InOffset], fill);
		T += TN_512;
		Compress32(m_digestState, 0);
		InOffset += fill;
		Length -= fill;
		m_dataLen = 0;
	}

	// compress data until enough for a block
	while (Length > 63)
	{
		T += TN_512;
		Compress32(Input, InOffset);
		InOffset += 64;
		Length -= 64;
	}

	if (Length != 0)
	{
		memcpy(&m_digestState[m_dataLen], &Input[InOffset], Length);
		m_dataLen += Length;
	}
	else
	{
		m_dataLen = 0;
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
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_dataLen = 0;
		m_isNullT = false;
		T = 0;

		CEX::Utility::IntUtils::ClearVector(m_hashVal);
		CEX::Utility::IntUtils::ClearVector(m_salt32);
		CEX::Utility::IntUtils::ClearVector(M);
		CEX::Utility::IntUtils::ClearVector(V);
	}
}

size_t Blake256::DoFinal(std::vector<byte> &Output, const size_t OutOffset)
{
	if (Output.size() - OutOffset < DIGEST_SIZE)
		throw CryptoDigestException("Blake256:DoFinal", "The Output buffer is too short!");

	std::vector<byte> msgLen(8);
	ulong len = T + ((uint64_t)m_dataLen << 3);
	CEX::Utility::IntUtils::Be32ToBytes((uint)(len >> 32) & 0xFFFFFFFFU, msgLen, 0);
	CEX::Utility::IntUtils::Be32ToBytes((uint)(len & 0xFFFFFFFFU), msgLen, 4);

	// special case of one padding byte
	if (m_dataLen == PAD_LENGTH)
	{
		T -= 8;
		std::vector<byte> one(1, 0x81);
		BlockUpdate(one, 0, 1);
	}
	else
	{
		if (m_dataLen < PAD_LENGTH)
		{
			// enough space to fill the block
			if (m_dataLen == 0)
				m_isNullT = true;

			T -= TN_440 - ((uint64_t)m_dataLen << 3);
			BlockUpdate(m_padding, 0, PAD_LENGTH - m_dataLen);
		}
		else
		{
			// not enough space, need 2 compressions
			T -= TN_512 - ((uint64_t)m_dataLen << 3);
			BlockUpdate(m_padding, 0, 64 - m_dataLen);
			T -= TN_440;
			BlockUpdate(m_padding, 1, PAD_LENGTH);
			m_isNullT = true;
		}

		std::vector<byte> one(1, 0x01);
		BlockUpdate(one, 0, 1);
		T -= 8;
	}

	T -= 64;
	BlockUpdate(msgLen, 0, 8);
	std::vector<byte> digest(32, 0);

	CEX::Utility::IntUtils::Be32ToBytes(m_hashVal[0], digest, 0);
	CEX::Utility::IntUtils::Be32ToBytes(m_hashVal[1], digest, 4);
	CEX::Utility::IntUtils::Be32ToBytes(m_hashVal[2], digest, 8);
	CEX::Utility::IntUtils::Be32ToBytes(m_hashVal[3], digest, 12);
	CEX::Utility::IntUtils::Be32ToBytes(m_hashVal[4], digest, 16);
	CEX::Utility::IntUtils::Be32ToBytes(m_hashVal[5], digest, 20);
	CEX::Utility::IntUtils::Be32ToBytes(m_hashVal[6], digest, 24);
	CEX::Utility::IntUtils::Be32ToBytes(m_hashVal[7], digest, 28);

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
	int P0 = m_ftSigma[P];
	int P1 = m_ftSigma[P + 1];

	V[A] += V[B] + (M[P0] ^ m_C32[P1]);
	V[D] = CEX::Utility::IntUtils::RotateRight(V[D] ^ V[A], 16);
	V[C] += V[D];
	V[B] = CEX::Utility::IntUtils::RotateRight(V[B] ^ V[C], 12);
	V[A] += V[B] + (M[P1] ^ m_C32[P0]);
	V[D] = CEX::Utility::IntUtils::RotateRight(V[D] ^ V[A], 8);
	V[C] += V[D];
	V[B] = CEX::Utility::IntUtils::RotateRight(V[B] ^ V[C], 7);
}

void Blake256::Compress32(const std::vector<byte> &Block, size_t Offset)
{
	M[0] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset);
	M[1] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 4);
	M[2] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 8);
	M[3] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 12);
	M[4] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 16);
	M[5] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 20);
	M[6] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 24);
	M[7] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 28);
	M[8] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 32);
	M[9] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 36);
	M[10] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 40);
	M[11] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 44);
	M[12] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 48);
	M[13] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 52);
	M[14] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 56);
	M[15] = CEX::Utility::IntUtils::BytesToBe32(Block, Offset + 60);

	V[0] = m_hashVal[0];
	V[1] = m_hashVal[1];
	V[2] = m_hashVal[2];
	V[3] = m_hashVal[3];
	V[4] = m_hashVal[4];
	V[5] = m_hashVal[5];
	V[6] = m_hashVal[6];
	V[7] = m_hashVal[7];
	V[8] = m_salt32[0] ^ 0x243F6A88U;
	V[9] = m_salt32[1] ^ 0x85A308D3U;
	V[10] = m_salt32[2] ^ 0x13198A2EU;
	V[11] = m_salt32[3] ^ 0x03707344U;
	V[12] = 0xA4093822U;
	V[13] = 0x299F31D0U;
	V[14] = 0x082EFA98U;
	V[15] = 0xEC4E6C89U;

	if (!m_isNullT)
	{
		uint uLen = (uint)(T & 0xFFFFFFFFU);
		V[12] ^= uLen;
		V[13] ^= uLen;
		uLen = (uint)((T >> 32) & 0xFFFFFFFFU);
		V[14] ^= uLen;
		V[15] ^= uLen;
	}

	uint index = 0;
	do
	{
		G32BLK(index);
		index++;

	} while (index != ROUNDS);

	m_hashVal[0] ^= V[0];
	m_hashVal[1] ^= V[1];
	m_hashVal[2] ^= V[2];
	m_hashVal[3] ^= V[3];
	m_hashVal[4] ^= V[4];
	m_hashVal[5] ^= V[5];
	m_hashVal[6] ^= V[6];
	m_hashVal[7] ^= V[7];
	m_hashVal[0] ^= V[8];
	m_hashVal[1] ^= V[9];
	m_hashVal[2] ^= V[10];
	m_hashVal[3] ^= V[11];
	m_hashVal[4] ^= V[12];
	m_hashVal[5] ^= V[13];
	m_hashVal[6] ^= V[14];
	m_hashVal[7] ^= V[15];
	m_hashVal[0] ^= m_salt32[0];
	m_hashVal[1] ^= m_salt32[1];
	m_hashVal[2] ^= m_salt32[2];
	m_hashVal[3] ^= m_salt32[3];
	m_hashVal[4] ^= m_salt32[0];
	m_hashVal[5] ^= m_salt32[1];
	m_hashVal[6] ^= m_salt32[2];
	m_hashVal[7] ^= m_salt32[3];
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
	m_hashVal =
	{
		0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
		0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
	};

	std::fill(m_salt32.begin(), m_salt32.end(), 0);
	T = 0;
	m_dataLen = 0;
	m_isNullT = false;
	std::fill(m_digestState.begin(), m_digestState.end(), 0);
}

NAMESPACE_DIGESTEND