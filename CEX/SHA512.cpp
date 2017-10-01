#include "SHA512.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "ParallelUtils.h"

NAMESPACE_DIGEST

const std::string SHA512::CLASS_NAME("SHA512");

// *** Properties *** //

size_t SHA512::BlockSize() 
{ 
	return BLOCK_SIZE; 
}

size_t SHA512::DigestSize() 
{ 
	return DIGEST_SIZE; 
}

const Digests SHA512::Enumeral()
{ 
	return Digests::SHA512; 
}

const bool SHA512::IsParallel() 
{ 
	return m_parallelProfile.IsParallel(); 
}

const std::string SHA512::Name() 
{
	if (m_parallelProfile.IsParallel())
		return CLASS_NAME + "-P" + Utility::IntUtils::ToString(m_parallelProfile.ParallelMaxDegree());
	else
		return CLASS_NAME;
}

const size_t SHA512::ParallelBlockSize() 
{ 
	return m_parallelProfile.ParallelBlockSize(); 
}

ParallelOptions &SHA512::ParallelProfile()
{
	return m_parallelProfile; 
}

//~~~Constructor~~~//

SHA512::SHA512(bool Parallel)
	:
	m_treeParams(DIGEST_SIZE, static_cast<uint>(BLOCK_SIZE), DEF_PRLDEGREE),
	m_isDestroyed(false),
	m_msgBuffer(Parallel ? DEF_PRLDEGREE * BLOCK_SIZE : BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, DEF_PRLDEGREE),
	m_dgtState(Parallel ? DEF_PRLDEGREE : 1)
{
	if (m_parallelProfile.IsParallel())
		m_parallelProfile.IsParallel() = Parallel;

	Reset();
}

SHA512::SHA512(SHA2Params &Params)
	:
	m_treeParams(Params),
	m_dgtState(1),
	m_isDestroyed(false),
	m_msgBuffer(BLOCK_SIZE),
	m_msgLength(0),
	m_parallelProfile(BLOCK_SIZE, false, STATE_PRECACHED, false, m_treeParams.FanOut())
{
	if (m_treeParams.FanOut() > 1)
	{
		m_dgtState.resize(m_treeParams.FanOut());
		m_msgBuffer.resize(m_treeParams.FanOut() * BLOCK_SIZE);
	}
	else if (m_parallelProfile.IsParallel())
	{
		m_parallelProfile.IsParallel() = false;
	}

	Reset();
}

SHA512::~SHA512()
{
	Destroy();
}

//~~~Public Functions~~~//

void SHA512::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(DIGEST_SIZE);
	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

void SHA512::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_msgLength = 0;

		for (size_t i = 0; i < m_dgtState.size(); ++i)
			m_dgtState[i].Reset();

		Utility::IntUtils::ClearVector(m_dgtState);
		Utility::IntUtils::ClearVector(m_msgBuffer);
	}
}

size_t SHA512::Finalize(std::vector<byte> &Output, const size_t OutOffset)
{
	CEXASSERT(Output.size() - OutOffset >= DIGEST_SIZE, "The Output buffer is too short!");

	if (m_parallelProfile.IsParallel())
	{
		// pad buffer with zeros
		if (m_msgLength < m_msgBuffer.size())
			Utility::MemUtils::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);

		// process buffer
		if (m_msgLength != 0)
		{
			size_t blkCtr = 0;

			while (m_msgLength != 0)
			{
				const size_t MSGRMD = (m_msgLength >= BLOCK_SIZE) ? BLOCK_SIZE : m_msgLength;
				HashFinal(m_msgBuffer, blkCtr * BLOCK_SIZE, MSGRMD, m_dgtState[blkCtr]);
				m_msgLength -= MSGRMD;
				++blkCtr;
			}
		}

		// initialize root state
		SHA512State rootState;
		rootState.Reset();

		// add state blocks as contiguous message input
		for (size_t i = 0; i < m_dgtState.size(); ++i)
		{
			Utility::IntUtils::BeULL512ToBlock(m_dgtState[i].H, 0, m_msgBuffer, i * BLOCK_SIZE);
			m_msgLength += DIGEST_SIZE;
		}

		// compress full blocks
		size_t blkOff = 0;
		if (m_msgLength > BLOCK_SIZE)
		{
			const size_t BLKRMD = m_msgLength - (m_msgLength % BLOCK_SIZE);

			for (size_t i = 0; i < BLKRMD / BLOCK_SIZE; ++i)
				Compress(m_msgBuffer, i * BLOCK_SIZE, rootState);

			m_msgLength -= BLKRMD;
			blkOff = BLKRMD;
		}

		// finalize and store
		HashFinal(m_msgBuffer, blkOff, m_msgLength, rootState);
		Utility::IntUtils::BeULL512ToBlock(rootState.H, 0, Output, OutOffset);
	}
	else
	{
		// finalize and store
		HashFinal(m_msgBuffer, 0, m_msgLength, m_dgtState[0]);
		Utility::IntUtils::BeULL512ToBlock(m_dgtState[0].H, 0, Output, OutOffset);
	}

	Reset();

	return DIGEST_SIZE;
}

void SHA512::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoDigestException("SHA512:ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree > 254)
		throw CryptoDigestException("SHA512:ParallelMaxDegree", "Parallel degree can not exceed 254!");
	if (Degree % 2 != 0)
		throw CryptoDigestException("SHA512:ParallelMaxDegree", "Parallel degree must be an even number!");

	m_parallelProfile.SetMaxDegree(Degree);
	m_dgtState.clear();
	m_dgtState.resize(Degree);
	m_msgBuffer.clear();
	m_msgBuffer.resize(Degree * BLOCK_SIZE);

	Reset();
}

void SHA512::Reset()
{
	m_msgLength = 0;
	Utility::MemUtils::Clear(m_msgBuffer, 0, m_msgBuffer.size());

	for (size_t i = 0; i < m_dgtState.size(); ++i)
	{
		m_dgtState[i].Reset();

		if (m_parallelProfile.IsParallel())
		{
			m_treeParams.NodeOffset() = static_cast<uint>(i);
			Compress(m_treeParams.ToBytes(), 0, m_dgtState[i]);
		}
	}
}

void SHA512::Update(byte Input)
{
	std::vector<byte> inp(1, Input);
	Update(inp, 0, 1);
}

void SHA512::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CEXASSERT(Input.size() - InOffset >= Length, "The Output buffer is too short!");

	if (Length == 0)
		return;

	if (m_parallelProfile.IsParallel())
	{
		if (m_msgLength != 0 && Length + m_msgLength >= m_msgBuffer.size())
		{
			// fill buffer
			const size_t RMDLEN = m_msgBuffer.size() - m_msgLength;
			if (RMDLEN != 0)
				Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);

			// empty the message buffer
			Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset](size_t i)
			{
				Compress(m_msgBuffer, i * BLOCK_SIZE, m_dgtState[i]);
			});

			m_msgLength = 0;
			Length -= RMDLEN;
			InOffset += RMDLEN;
		}

		if (Length >= m_parallelProfile.ParallelBlockSize())
		{
			// calculate working set size
			const size_t PRCLEN = Length - (Length % m_parallelProfile.ParallelBlockSize());

			// process large blocks
			Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRCLEN](size_t i)
			{
				ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_dgtState[i], PRCLEN);
			});

			Length -= PRCLEN;
			InOffset += PRCLEN;
		}

		if (Length >= m_parallelProfile.ParallelMinimumSize())
		{
			const size_t PRMLEN = Length - (Length % m_parallelProfile.ParallelMinimumSize());
			Utility::ParallelUtils::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, PRMLEN](size_t i)
			{
				ProcessLeaf(Input, InOffset + (i * BLOCK_SIZE), m_dgtState[i], PRMLEN);
			});

			Length -= PRMLEN;
			InOffset += PRMLEN;
		}
	}
	else
	{
		if (m_msgLength != 0 && (m_msgLength + Length >= BLOCK_SIZE))
		{
			const size_t RMDLEN = BLOCK_SIZE - m_msgLength;
			if (RMDLEN != 0)
				Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);

			Compress(m_msgBuffer, 0, m_dgtState[0]);
			m_msgLength = 0;
			InOffset += RMDLEN;
			Length -= RMDLEN;
		}

		// sequential loop through blocks
		while (Length > BLOCK_SIZE)
		{
			Compress(Input, InOffset, m_dgtState[0]);
			InOffset += BLOCK_SIZE;
			Length -= BLOCK_SIZE;
		}
	}

	// store unaligned bytes
	if (Length != 0)
	{
		Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
		m_msgLength += Length;
	}
}

//~~~Private Functions~~~//

ulong SHA512::BigSigma0(ulong W)
{
	return ((W << 36) | (W >> 28)) ^ ((W << 30) | (W >> 34)) ^ ((W << 25) | (W >> 39));
}

ulong SHA512::BigSigma1(ulong W)
{
	return ((W << 50) | (W >> 14)) ^ ((W << 46) | (W >> 18)) ^ ((W << 23) | (W >> 41));
}

ulong SHA512::Ch(ulong B, ulong C, ulong D)
{
	return (B & C) ^ (~B & D);
}

void SHA512::Compress(const std::vector<byte> &Input, size_t InOffset, SHA512State &State)
{
	ulong A = State.H[0];
	ulong B = State.H[1];
	ulong C = State.H[2];
	ulong D = State.H[3];
	ulong E = State.H[4];
	ulong F = State.H[5];
	ulong G = State.H[6];
	ulong H = State.H[7];
	ulong W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;

	W0 = IntUtils::BeBytesTo64(Input, InOffset);
	Round(A, B, C, D, E, F, G, H, W0, 0x428a2f98d728ae22);
	W1 = IntUtils::BeBytesTo64(Input, InOffset + 8);
	Round(H, A, B, C, D, E, F, G, W1, 0x7137449123ef65cd);
	W2 = IntUtils::BeBytesTo64(Input, InOffset + 16);
	Round(G, H, A, B, C, D, E, F, W2, 0xb5c0fbcfec4d3b2f);
	W3 = IntUtils::BeBytesTo64(Input, InOffset + 24);
	Round(F, G, H, A, B, C, D, E, W3, 0xe9b5dba58189dbbc);
	W4 = IntUtils::BeBytesTo64(Input, InOffset + 32);
	Round(E, F, G, H, A, B, C, D, W4, 0x3956c25bf348b538);
	W5 = IntUtils::BeBytesTo64(Input, InOffset + 40);
	Round(D, E, F, G, H, A, B, C, W5, 0x59f111f1b605d019);
	W6 = IntUtils::BeBytesTo64(Input, InOffset + 48);
	Round(C, D, E, F, G, H, A, B, W6, 0x923f82a4af194f9b);
	W7 = IntUtils::BeBytesTo64(Input, InOffset + 56);
	Round(B, C, D, E, F, G, H, A, W7, 0xab1c5ed5da6d8118);
	W8 = IntUtils::BeBytesTo64(Input, InOffset + 64);
	Round(A, B, C, D, E, F, G, H, W8, 0xd807aa98a3030242);
	W9 = IntUtils::BeBytesTo64(Input, InOffset + 72);
	Round(H, A, B, C, D, E, F, G, W9, 0x12835b0145706fbe);
	W10 = IntUtils::BeBytesTo64(Input, InOffset + 80);
	Round(G, H, A, B, C, D, E, F, W10, 0x243185be4ee4b28c);
	W11 = IntUtils::BeBytesTo64(Input, InOffset + 88);
	Round(F, G, H, A, B, C, D, E, W11, 0x550c7dc3d5ffb4e2);
	W12 = IntUtils::BeBytesTo64(Input, InOffset + 96);
	Round(E, F, G, H, A, B, C, D, W12, 0x72be5d74f27b896f);
	W13 = IntUtils::BeBytesTo64(Input, InOffset + 104);
	Round(D, E, F, G, H, A, B, C, W13, 0x80deb1fe3b1696b1);
	W14 = IntUtils::BeBytesTo64(Input, InOffset + 112);
	Round(C, D, E, F, G, H, A, B, W14, 0x9bdc06a725c71235);
	W15 = IntUtils::BeBytesTo64(Input, InOffset + 120);
	Round(B, C, D, E, F, G, H, A, W15, 0xc19bf174cf692694);

	W0 += Sigma1(W14) + W9 + Sigma0(W1);
	Round(A, B, C, D, E, F, G, H, W0, 0xe49b69c19ef14ad2);
	W1 += Sigma1(W15) + W10 + Sigma0(W2);
	Round(H, A, B, C, D, E, F, G, W1, 0xefbe4786384f25e3);
	W2 += Sigma1(W0) + W11 + Sigma0(W3);
	Round(G, H, A, B, C, D, E, F, W2, 0x0fc19dc68b8cd5b5);
	W3 += Sigma1(W1) + W12 + Sigma0(W4);
	Round(F, G, H, A, B, C, D, E, W3, 0x240ca1cc77ac9c65);
	W4 += Sigma1(W2) + W13 + Sigma0(W5);
	Round(E, F, G, H, A, B, C, D, W4, 0x2de92c6f592b0275);
	W5 += Sigma1(W3) + W14 + Sigma0(W6);
	Round(D, E, F, G, H, A, B, C, W5, 0x4a7484aa6ea6e483);
	W6 += Sigma1(W4) + W15 + Sigma0(W7);
	Round(C, D, E, F, G, H, A, B, W6, 0x5cb0a9dcbd41fbd4);
	W7 += Sigma1(W5) + W0 + Sigma0(W8);
	Round(B, C, D, E, F, G, H, A, W7, 0x76f988da831153b5);
	W8 += Sigma1(W6) + W1 + Sigma0(W9);
	Round(A, B, C, D, E, F, G, H, W8, 0x983e5152ee66dfab);
	W9 += Sigma1(W7) + W2 + Sigma0(W10);
	Round(H, A, B, C, D, E, F, G, W9, 0xa831c66d2db43210);
	W10 += Sigma1(W8) + W3 + Sigma0(W11);
	Round(G, H, A, B, C, D, E, F, W10, 0xb00327c898fb213f);
	W11 += Sigma1(W9) + W4 + Sigma0(W12);
	Round(F, G, H, A, B, C, D, E, W11, 0xbf597fc7beef0ee4);
	W12 += Sigma1(W10) + W5 + Sigma0(W13);
	Round(E, F, G, H, A, B, C, D, W12, 0xc6e00bf33da88fc2);
	W13 += Sigma1(W11) + W6 + Sigma0(W14);
	Round(D, E, F, G, H, A, B, C, W13, 0xd5a79147930aa725);
	W14 += Sigma1(W12) + W7 + Sigma0(W15);
	Round(C, D, E, F, G, H, A, B, W14, 0x06ca6351e003826f);
	W15 += Sigma1(W13) + W8 + Sigma0(W0);
	Round(B, C, D, E, F, G, H, A, W15, 0x142929670a0e6e70);

	W0 += Sigma1(W14) + W9 + Sigma0(W1);
	Round(A, B, C, D, E, F, G, H, W0, 0x27b70a8546d22ffc);
	W1 += Sigma1(W15) + W10 + Sigma0(W2);
	Round(H, A, B, C, D, E, F, G, W1, 0x2e1b21385c26c926);
	W2 += Sigma1(W0) + W11 + Sigma0(W3);
	Round(G, H, A, B, C, D, E, F, W2, 0x4d2c6dfc5ac42aed);
	W3 += Sigma1(W1) + W12 + Sigma0(W4);
	Round(F, G, H, A, B, C, D, E, W3, 0x53380d139d95b3df);
	W4 += Sigma1(W2) + W13 + Sigma0(W5);
	Round(E, F, G, H, A, B, C, D, W4, 0x650a73548baf63de);
	W5 += Sigma1(W3) + W14 + Sigma0(W6);
	Round(D, E, F, G, H, A, B, C, W5, 0x766a0abb3c77b2a8);
	W6 += Sigma1(W4) + W15 + Sigma0(W7);
	Round(C, D, E, F, G, H, A, B, W6, 0x81c2c92e47edaee6);
	W7 += Sigma1(W5) + W0 + Sigma0(W8);
	Round(B, C, D, E, F, G, H, A, W7, 0x92722c851482353b);
	W8 += Sigma1(W6) + W1 + Sigma0(W9);
	Round(A, B, C, D, E, F, G, H, W8, 0xa2bfe8a14cf10364);
	W9 += Sigma1(W7) + W2 + Sigma0(W10);
	Round(H, A, B, C, D, E, F, G, W9, 0xa81a664bbc423001);
	W10 += Sigma1(W8) + W3 + Sigma0(W11);
	Round(G, H, A, B, C, D, E, F, W10, 0xc24b8b70d0f89791);
	W11 += Sigma1(W9) + W4 + Sigma0(W12);
	Round(F, G, H, A, B, C, D, E, W11, 0xc76c51a30654be30);
	W12 += Sigma1(W10) + W5 + Sigma0(W13);
	Round(E, F, G, H, A, B, C, D, W12, 0xd192e819d6ef5218);
	W13 += Sigma1(W11) + W6 + Sigma0(W14);
	Round(D, E, F, G, H, A, B, C, W13, 0xd69906245565a910);
	W14 += Sigma1(W12) + W7 + Sigma0(W15);
	Round(C, D, E, F, G, H, A, B, W14, 0xf40e35855771202a);
	W15 += Sigma1(W13) + W8 + Sigma0(W0);
	Round(B, C, D, E, F, G, H, A, W15, 0x106aa07032bbd1b8);

	W0 += Sigma1(W14) + W9 + Sigma0(W1);
	Round(A, B, C, D, E, F, G, H, W0, 0x19a4c116b8d2d0c8);
	W1 += Sigma1(W15) + W10 + Sigma0(W2);
	Round(H, A, B, C, D, E, F, G, W1, 0x1e376c085141ab53);
	W2 += Sigma1(W0) + W11 + Sigma0(W3);
	Round(G, H, A, B, C, D, E, F, W2, 0x2748774cdf8eeb99);
	W3 += Sigma1(W1) + W12 + Sigma0(W4);
	Round(F, G, H, A, B, C, D, E, W3, 0x34b0bcb5e19b48a8);
	W4 += Sigma1(W2) + W13 + Sigma0(W5);
	Round(E, F, G, H, A, B, C, D, W4, 0x391c0cb3c5c95a63);
	W5 += Sigma1(W3) + W14 + Sigma0(W6);
	Round(D, E, F, G, H, A, B, C, W5, 0x4ed8aa4ae3418acb);
	W6 += Sigma1(W4) + W15 + Sigma0(W7);
	Round(C, D, E, F, G, H, A, B, W6, 0x5b9cca4f7763e373);
	W7 += Sigma1(W5) + W0 + Sigma0(W8);
	Round(B, C, D, E, F, G, H, A, W7, 0x682e6ff3d6b2b8a3);
	W8 += Sigma1(W6) + W1 + Sigma0(W9);
	Round(A, B, C, D, E, F, G, H, W8, 0x748f82ee5defb2fc);
	W9 += Sigma1(W7) + W2 + Sigma0(W10);
	Round(H, A, B, C, D, E, F, G, W9, 0x78a5636f43172f60);
	W10 += Sigma1(W8) + W3 + Sigma0(W11);
	Round(G, H, A, B, C, D, E, F, W10, 0x84c87814a1f0ab72);
	W11 += Sigma1(W9) + W4 + Sigma0(W12);
	Round(F, G, H, A, B, C, D, E, W11, 0x8cc702081a6439ec);
	W12 += Sigma1(W10) + W5 + Sigma0(W13);
	Round(E, F, G, H, A, B, C, D, W12, 0x90befffa23631e28);
	W13 += Sigma1(W11) + W6 + Sigma0(W14);
	Round(D, E, F, G, H, A, B, C, W13, 0xa4506cebde82bde9);
	W14 += Sigma1(W12) + W7 + Sigma0(W15);
	Round(C, D, E, F, G, H, A, B, W14, 0xbef9a3f7b2c67915);
	W15 += Sigma1(W13) + W8 + Sigma0(W0);
	Round(B, C, D, E, F, G, H, A, W15, 0xc67178f2e372532b);

	W0 += Sigma1(W14) + W9 + Sigma0(W1);
	Round(A, B, C, D, E, F, G, H, W0, 0xca273eceea26619c);
	W1 += Sigma1(W15) + W10 + Sigma0(W2);
	Round(H, A, B, C, D, E, F, G, W1, 0xd186b8c721c0c207);
	W2 += Sigma1(W0) + W11 + Sigma0(W3);
	Round(G, H, A, B, C, D, E, F, W2, 0xeada7dd6cde0eb1e);
	W3 += Sigma1(W1) + W12 + Sigma0(W4);
	Round(F, G, H, A, B, C, D, E, W3, 0xf57d4f7fee6ed178);
	W4 += Sigma1(W2) + W13 + Sigma0(W5);
	Round(E, F, G, H, A, B, C, D, W4, 0x06f067aa72176fba);
	W5 += Sigma1(W3) + W14 + Sigma0(W6);
	Round(D, E, F, G, H, A, B, C, W5, 0x0a637dc5a2c898a6);
	W6 += Sigma1(W4) + W15 + Sigma0(W7);
	Round(C, D, E, F, G, H, A, B, W6, 0x113f9804bef90dae);
	W7 += Sigma1(W5) + W0 + Sigma0(W8);
	Round(B, C, D, E, F, G, H, A, W7, 0x1b710b35131c471b);
	W8 += Sigma1(W6) + W1 + Sigma0(W9);
	Round(A, B, C, D, E, F, G, H, W8, 0x28db77f523047d84);
	W9 += Sigma1(W7) + W2 + Sigma0(W10);
	Round(H, A, B, C, D, E, F, G, W9, 0x32caab7b40c72493);
	W10 += Sigma1(W8) + W3 + Sigma0(W11);
	Round(G, H, A, B, C, D, E, F, W10, 0x3c9ebe0a15c9bebc);
	W11 += Sigma1(W9) + W4 + Sigma0(W12);
	Round(F, G, H, A, B, C, D, E, W11, 0x431d67c49c100d4c);
	W12 += Sigma1(W10) + W5 + Sigma0(W13);
	Round(E, F, G, H, A, B, C, D, W12, 0x4cc5d4becb3e42b6);
	W13 += Sigma1(W11) + W6 + Sigma0(W14);
	Round(D, E, F, G, H, A, B, C, W13, 0x597f299cfc657e2a);
	W14 += Sigma1(W12) + W7 + Sigma0(W15);
	Round(C, D, E, F, G, H, A, B, W14, 0x5fcb6fab3ad6faec);
	W15 += Sigma1(W13) + W8 + Sigma0(W0);
	Round(B, C, D, E, F, G, H, A, W15, 0x6c44198c4a475817);

	State.H[0] += A;
	State.H[1] += B;
	State.H[2] += C;
	State.H[3] += D;
	State.H[4] += E;
	State.H[5] += F;
	State.H[6] += G;
	State.H[7] += H;

	State.Increase(BLOCK_SIZE);
}

void SHA512::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, SHA512State &State)
{
	State.Increase(Length);
	ulong bitLen = (State.T[0] << 3);

	if (Length == BLOCK_SIZE)
	{
		Compress(Input, InOffset, State);
		Length = 0;
	}

	Input[InOffset + Length] = (byte)128;
	++Length;

	// padding
	if (Length < BLOCK_SIZE)
		Utility::MemUtils::Clear(Input, InOffset + Length, BLOCK_SIZE - Length);

	if (Length > 112)
	{
		Compress(Input, InOffset, State);
		Utility::MemUtils::Clear(Input, InOffset, BLOCK_SIZE);
	}

	// finalize state with counter and last compression
	Utility::IntUtils::Be64ToBytes(State.T[1], Input, InOffset + 112);
	Utility::IntUtils::Be64ToBytes(bitLen, Input, InOffset + 120);
	Compress(Input, InOffset, State);
}

ulong SHA512::Maj(ulong B, ulong C, ulong D)
{
	return (B & C) ^ (B & D) ^ (C & D);
}

void SHA512::ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, SHA512State &State, ulong Length)
{
	do
	{
		Compress(Input, InOffset, State);
		InOffset += m_parallelProfile.ParallelMinimumSize();
		Length -= m_parallelProfile.ParallelMinimumSize();
	} 
	while (Length > 0);
}

void SHA512::Round(ulong A, ulong B, ulong C, ulong &D, ulong E, ulong F, ulong G, ulong &H, ulong M, ulong P)
{
	ulong R0 = H + BigSigma1(E) + Ch(E, F, G) + P + M;
	D += R0;
	H = R0 + BigSigma0(A) + Maj(A, B, C);
}

ulong SHA512::Sigma0(ulong W)
{
	return ((W << 63) | (W >> 1)) ^ ((W << 56) | (W >> 8)) ^ (W >> 7);
}

ulong SHA512::Sigma1(ulong W)
{
	return ((W << 45) | (W >> 19)) ^ ((W << 3) | (W >> 61)) ^ (W >> 6);
}

NAMESPACE_DIGESTEND