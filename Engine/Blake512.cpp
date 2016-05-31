#include "Blake512.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

static constexpr ulong m_C64[] =
{
	0x243F6A8885A308D3UL, 0x13198A2E03707344UL, 0xA4093822299F31D0UL, 0x082EFA98EC4E6C89UL,
	0x452821E638D01377UL, 0xBE5466CF34E90C6CUL, 0xC0AC29B7C97C50DDUL, 0x3F84D5B5B5470917UL,
	0x9216D5D98979FB1BUL, 0xD1310BA698DFB5ACUL, 0x2FFD72DBD01ADFB7UL, 0xB8E1AFED6A267E96UL,
	0xBA7C9045F12C7F99UL, 0x24A19947B3916CF7UL, 0x0801F2E2858EFC16UL, 0x636920D871574E69UL
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
	7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
	9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
	2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9
};

void Blake512::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if ((InOffset + Length) > Input.size())
		throw CryptoDigestException("Blake512:BlockUpdate", "The Input buffer is too short!");

	size_t fill = 128 - m_dataLen;

	// compress remaining data filled with new bits
	if ((m_dataLen != 0) && (Length >= fill))
	{
		memcpy(&m_digestState[m_dataLen], &Input[InOffset], fill);
		T += TN_1024;
		Compress64(m_digestState, 0);
		InOffset += fill;
		Length -= fill;
		m_dataLen = 0;
	}

	// compress data until enough for a block
	while (Length > 127)
	{
		T += TN_1024;
		Compress64(Input, InOffset);
		InOffset += 128;
		Length -= 128;
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

void Blake512::ComputeHash(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
}

void Blake512::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_dataLen = 0;
		m_isNullT = false;
		T = 0;

		CEX::Utility::IntUtils::ClearVector(m_hashVal);
		CEX::Utility::IntUtils::ClearVector(m_salt64);
		CEX::Utility::IntUtils::ClearVector(M);
		CEX::Utility::IntUtils::ClearVector(V);
	}
}

size_t Blake512::DoFinal(std::vector<byte> &Output, const size_t OutOffset)
{
	if (Output.size() - OutOffset < DIGEST_SIZE)
		throw CryptoDigestException("Blake512:DoFinal", "The Output buffer is too short!");

	std::vector<byte> msgLen(16);
	CEX::Utility::IntUtils::Be64ToBytes(T + ((ulong)m_dataLen << 3), msgLen, 8);

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

			T -= TN_888 - ((ulong)m_dataLen << 3);
			BlockUpdate(m_padding, 0, PAD_LENGTH - m_dataLen);
		}
		else
		{
			// not enough space, need 2 compressions 
			T -= TN_1024 - ((ulong)m_dataLen << 3);
			BlockUpdate(m_padding, 0, 128 - m_dataLen);
			T -= TN_888;
			BlockUpdate(m_padding, 1, PAD_LENGTH);
			m_isNullT = true;
		}

		std::vector<byte> one(1, 0x01);
		BlockUpdate(one, 0, 1);
		T -= 8;
	}

	T -= 128;
	BlockUpdate(msgLen, 0, 16);
	std::vector<byte> digest(64, 0);

	CEX::Utility::IntUtils::Be64ToBytes(m_hashVal[0], digest, 0);
	CEX::Utility::IntUtils::Be64ToBytes(m_hashVal[1], digest, 8);
	CEX::Utility::IntUtils::Be64ToBytes(m_hashVal[2], digest, 16);
	CEX::Utility::IntUtils::Be64ToBytes(m_hashVal[3], digest, 24);
	CEX::Utility::IntUtils::Be64ToBytes(m_hashVal[4], digest, 32);
	CEX::Utility::IntUtils::Be64ToBytes(m_hashVal[5], digest, 40);
	CEX::Utility::IntUtils::Be64ToBytes(m_hashVal[6], digest, 48);
	CEX::Utility::IntUtils::Be64ToBytes(m_hashVal[7], digest, 56);

	memcpy(&Output[OutOffset], &digest[0], digest.size());
	Reset();

	return Output.size();
}

void Blake512::Reset()
{
	Initialize();
}

void Blake512::Update(byte Input)
{
	std::vector<byte> one(1, Input);
	BlockUpdate(one, 0, 1);
}

// *** Protected Methods *** //

void Blake512::Compress64(const std::vector<byte> &pbBlock, size_t Offset)
{
	M[0] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset);
	M[1] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 8);
	M[2] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 16);
	M[3] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 24);
	M[4] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 32);
	M[5] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 40);
	M[6] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 48);
	M[7] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 56);
	M[8] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 64);
	M[9] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 72);
	M[10] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 80);
	M[11] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 88);
	M[12] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 96);
	M[13] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 104);
	M[14] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 112);
	M[15] = CEX::Utility::IntUtils::BytesToBe64(pbBlock, Offset + 120);

	V[0] = m_hashVal[0];
	V[1] = m_hashVal[1];
	V[2] = m_hashVal[2];
	V[3] = m_hashVal[3];
	V[4] = m_hashVal[4];
	V[5] = m_hashVal[5];
	V[6] = m_hashVal[6];
	V[7] = m_hashVal[7];
	V[8] = m_salt64[0] ^ 0x243F6A8885A308D3UL;
	V[9] = m_salt64[1] ^ 0x13198A2E03707344UL;
	V[10] = m_salt64[2] ^ 0xA4093822299F31D0UL;
	V[11] = m_salt64[3] ^ 0x082EFA98EC4E6C89UL;
	V[12] = 0x452821E638D01377UL;
	V[13] = 0xBE5466CF34E90C6CUL;
	V[14] = 0xC0AC29B7C97C50DDUL;
	V[15] = 0x3F84D5B5B5470917UL;

	if (!m_isNullT)
	{
		V[12] ^= T;
		V[13] ^= T;
	}

	//  do 16 rounds
	uint index = 0;
	do
	{
		G64BLK(index);
		index++;

	} while (index != ROUNDS);

	// finalization
	m_hashVal[0] ^= V[0];
	m_hashVal[1] ^= V[1];
	m_hashVal[2] ^= V[2];
	m_hashVal[3] ^= V[3];
	m_hashVal[4] ^= V[4];
	m_hashVal[5] ^= V[5];
	m_hashVal[6] ^= V[6];
	m_hashVal[7] ^= V[7];
	/*CEX::Utility::IntUtils::XOR8X64(V, 0, m_hashVal, 0);*/

	m_hashVal[0] ^= V[8];
	m_hashVal[1] ^= V[9];
	m_hashVal[2] ^= V[10];
	m_hashVal[3] ^= V[11];
	m_hashVal[4] ^= V[12];
	m_hashVal[5] ^= V[13];
	m_hashVal[6] ^= V[14];
	m_hashVal[7] ^= V[15];
	/*CEX::Utility::IntUtils::XOR8X64(V, 8, m_hashVal, 0);*/

	m_hashVal[0] ^= m_salt64[0];
	m_hashVal[1] ^= m_salt64[1];
	m_hashVal[2] ^= m_salt64[2];
	m_hashVal[3] ^= m_salt64[3];
	/*CEX::Utility::IntUtils::XOR4X64(m_salt64, 0, m_hashVal, 0);*/

	m_hashVal[4] ^= m_salt64[0];
	m_hashVal[5] ^= m_salt64[1];
	m_hashVal[6] ^= m_salt64[2];
	m_hashVal[7] ^= m_salt64[3];
	/*CEX::Utility::IntUtils::XOR4X64(m_salt64, 0, m_hashVal, 4);*/
}

void Blake512::G64BLK(uint Index)
{
	G64(0, 4, 8, 12, Index, 0);
	G64(1, 5, 9, 13, Index, 2);
	G64(2, 6, 10, 14, Index, 4);
	G64(3, 7, 11, 15, Index, 6);
	G64(3, 4, 9, 14, Index, 14);
	G64(2, 7, 8, 13, Index, 12);
	G64(0, 5, 10, 15, Index, 8);
	G64(1, 6, 11, 12, Index, 10);
}

void Blake512::G64(uint A, uint B, uint C, uint D, uint R, uint I)
{
	int P = (R << 4) + I;
	int P0 = m_ftSigma[P];
	int P1 = m_ftSigma[P + 1];

	// initialization
	V[A] += V[B] + (M[P0] ^ m_C64[P1]);
	V[D] = CEX::Utility::IntUtils::RotateFixRight64(V[D] ^ V[A], 32);
	V[C] += V[D];
	V[B] = CEX::Utility::IntUtils::RotateFixRight64(V[B] ^ V[C], 25);
	V[A] += V[B] + (M[P1] ^ m_C64[P0]);
	V[D] = CEX::Utility::IntUtils::RotateFixRight64(V[D] ^ V[A], 16);
	V[C] += V[D];
	V[B] = CEX::Utility::IntUtils::RotateFixRight64(V[B] ^ V[C], 11);
}

void Blake512::Initialize()
{
	m_hashVal =
	{
		0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
		0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
	};

	std::fill(m_salt64.begin(), m_salt64.end(), 0);
	T = 0;
	m_dataLen = 0;
	m_isNullT = false;
	std::fill(m_digestState.begin(), m_digestState.end(), 0);
}

NAMESPACE_DIGESTEND