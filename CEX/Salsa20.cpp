#include "Salsa20.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

#if defined(HAS_AVX)
#	include "UInt256.h"
#elif defined(HAS_MINSSE)
#	include "UInt128.h"
#endif

NAMESPACE_STREAM

void Salsa20::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_hasAVX = false;
		m_hasIntrinsics = false;
		m_isInitialized = false;
		m_processorCount = 0;
		m_isParallel = false;
		m_parallelBlockSize = 0;
		m_parallelMinimumSize = 0;
		m_rndCount = 0;

		CEX::Utility::IntUtils::ClearVector(m_ctrVector);
		CEX::Utility::IntUtils::ClearVector(m_wrkState);
		CEX::Utility::IntUtils::ClearVector(m_dstCode);
		CEX::Utility::IntUtils::ClearVector(m_threadVectors);
	}
}

void Salsa20::DetectCpu()
{
	CEX::Common::CpuDetect detect;
	m_hasIntrinsics = detect.HasMinIntrinsics();
	m_hasAVX = detect.HasAVX();
}

void Salsa20::Initialize(const CEX::Common::KeyParams &KeyParam)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (KeyParam.IV().size() != 8)
		throw CryptoSymmetricCipherException("Salsa20:Initialize", "Requires exactly 8 bytes of IV!");
	if (KeyParam.Key().size() != 16 && KeyParam.Key().size() != 32)
		throw CryptoSymmetricCipherException("Salsa20:Initialize", "Key must be 16 or 32 bytes!");
	if (IsParallel() && ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoSymmetricCipherException("Salsa20:Initialize", "The parallel block size is out of bounds!");
	if (IsParallel() && ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoSymmetricCipherException("Salsa20:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");
#endif

	if (m_dstCode.size() == 0)
	{
		std::string info;
		if (KeyParam.Key().size() == 16)
			info = "expand 16-byte k";
		else
			info = "expand 32-byte k";

		m_dstCode.reserve(info.size());
		for (size_t i = 0; i < info.size(); ++i)
			m_dstCode.push_back(info[i]);
	}

	Reset();
	SetKey(KeyParam.Key(), KeyParam.IV());
	m_isInitialized = true;
}

void Salsa20::Reset()
{
	m_ctrVector[0] = 0;
	m_ctrVector[1] = 0;
}

void Salsa20::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	ProcessBlock(Input, 0, Output, 0, Input.size());
}

void Salsa20::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	ProcessBlock(Input, InOffset, Output, OutOffset, m_isParallel ? m_parallelBlockSize : BLOCK_SIZE);
}

void Salsa20::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	ProcessBlock(Input, InOffset, Output, OutOffset, Length);
}

// ** Key Schedule ** //

void Salsa20::SetKey(const std::vector<byte> &Key, const std::vector<byte> &Iv)
{
	if (Key.size() == 32)
	{
		m_wrkState[0] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 0);
		m_wrkState[1] = CEX::Utility::IntUtils::BytesToLe32(Key, 0);
		m_wrkState[2] = CEX::Utility::IntUtils::BytesToLe32(Key, 4);
		m_wrkState[3] = CEX::Utility::IntUtils::BytesToLe32(Key, 8);
		m_wrkState[4] = CEX::Utility::IntUtils::BytesToLe32(Key, 12);
		m_wrkState[5] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 4);
		m_wrkState[6] = CEX::Utility::IntUtils::BytesToLe32(Iv, 0);
		m_wrkState[7] = CEX::Utility::IntUtils::BytesToLe32(Iv, 4);
		m_wrkState[8] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 8);
		m_wrkState[9] = CEX::Utility::IntUtils::BytesToLe32(Key, 16);
		m_wrkState[10] = CEX::Utility::IntUtils::BytesToLe32(Key, 20);
		m_wrkState[11] = CEX::Utility::IntUtils::BytesToLe32(Key, 24);
		m_wrkState[12] = CEX::Utility::IntUtils::BytesToLe32(Key, 28);
		m_wrkState[13] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 12);
	}
	else
	{
		m_wrkState[0] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 0);
		m_wrkState[1] = CEX::Utility::IntUtils::BytesToLe32(Key, 0);
		m_wrkState[2] = CEX::Utility::IntUtils::BytesToLe32(Key, 4);
		m_wrkState[3] = CEX::Utility::IntUtils::BytesToLe32(Key, 8);
		m_wrkState[4] = CEX::Utility::IntUtils::BytesToLe32(Key, 12);
		m_wrkState[5] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 4);
		m_wrkState[6] = CEX::Utility::IntUtils::BytesToLe32(Iv, 0);
		m_wrkState[7] = CEX::Utility::IntUtils::BytesToLe32(Iv, 4);
		m_wrkState[8] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 8);
		m_wrkState[9] = CEX::Utility::IntUtils::BytesToLe32(Key, 0);
		m_wrkState[10] = CEX::Utility::IntUtils::BytesToLe32(Key, 4);
		m_wrkState[11] = CEX::Utility::IntUtils::BytesToLe32(Key, 8);
		m_wrkState[12] = CEX::Utility::IntUtils::BytesToLe32(Key, 12);
		m_wrkState[13] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 12);
	}
}

// ** Processing ** //

void Salsa20::Increase(const std::vector<uint> &Input, std::vector<uint> &Output, const size_t Length)
{
	Output = Input;

	for (size_t i = 0; i < Length; i++)
		Increment(Output);
}

void Salsa20::Increment(std::vector<uint> &Counter)
{
	if (++Counter[0] == 0)
		++Counter[1];
}

void Salsa20::Generate(std::vector<byte> &Output, const size_t OutOffset, std::vector<uint> &Counter, const size_t Length)
{
	size_t aln = Length - (Length % BLOCK_SIZE);
	size_t ctr = 0;

	const size_t BALN = Length - (Length % BLOCK_SIZE);
	const size_t BLK4 = 4 * BLOCK_SIZE;

	if (HasAVX() && Length >= 2 * BLK4)
	{
		const size_t BLK8 = 8 * BLOCK_SIZE;
		size_t paln = Length - (Length % BLK8);
		std::vector<uint> ctrBlk(16);

		// process 8 blocks (uses avx if available)
		while (ctr != paln)
		{
			memcpy(&ctrBlk[0], &Counter[0], 4);
			memcpy(&ctrBlk[8], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[1], &Counter[0], 4);
			memcpy(&ctrBlk[9], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[2], &Counter[0], 4);
			memcpy(&ctrBlk[10], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[3], &Counter[0], 4);
			memcpy(&ctrBlk[11], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[4], &Counter[0], 4);
			memcpy(&ctrBlk[12], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[5], &Counter[0], 4);
			memcpy(&ctrBlk[13], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[6], &Counter[0], 4);
			memcpy(&ctrBlk[14], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[7], &Counter[0], 4);
			memcpy(&ctrBlk[15], &Counter[1], 4);
			Increment(Counter);
			Transform512(Output, OutOffset + ctr, ctrBlk);
			ctr += BLK8;
		}
	}
	else if (HasIntrinsics() && Length >= BLK4)
	{
		size_t paln = Length - (Length % BLK4);
		std::vector<uint> ctrBlk(8);

		// process 4 blocks (uses sse intrinsics if available)
		while (ctr != paln)
		{
			memcpy(&ctrBlk[0], &Counter[0], 4);
			memcpy(&ctrBlk[4], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[1], &Counter[0], 4);
			memcpy(&ctrBlk[5], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[2], &Counter[0], 4);
			memcpy(&ctrBlk[6], &Counter[1], 4);
			Increment(Counter);
			memcpy(&ctrBlk[3], &Counter[0], 4);
			memcpy(&ctrBlk[7], &Counter[1], 4);
			Increment(Counter);
			Transform256(Output, OutOffset + ctr, ctrBlk);
			ctr += BLK4;
		}
	}

	while (ctr != aln)
	{
		Transform64(Output, OutOffset + ctr, Counter);
		Increment(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
		std::vector<byte> outputBlock(BLOCK_SIZE, 0);
		Transform64(outputBlock, 0, Counter);
		int fnlSize = Length % BLOCK_SIZE;
		memcpy(&Output[OutOffset + (Length - fnlSize)], &outputBlock[0], fnlSize);
		Increment(Counter);
	}
}

uint Salsa20::GetProcessorCount()
{
	return CEX::Utility::ParallelUtils::ProcessorCount();
}

void Salsa20::ProcessBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	size_t blkSize = (Length > Input.size() - InOffset) ? Input.size() - InOffset : Length;
	if (blkSize > Output.size() - OutOffset)
		blkSize = Output.size() - OutOffset;

	if (!m_isParallel || blkSize < m_parallelMinimumSize)
	{
		// generate random
		Generate(Output, OutOffset, m_ctrVector, blkSize);
		// output is input xor random
		size_t sze = blkSize - (blkSize % BLOCK_SIZE);

		if (sze != 0)
			CEX::Utility::IntUtils::XORBLK(Input, InOffset, Output, OutOffset, sze);

		// get the remaining bytes
		if (sze != blkSize)
		{
			for (size_t i = sze; i < blkSize; ++i)
				Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
	else
	{
		// parallel CTR processing //
		const size_t cnkSize = (blkSize / BLOCK_SIZE / m_processorCount) * BLOCK_SIZE;
		const size_t rndSize = cnkSize * m_processorCount;
		const size_t subSize = (cnkSize / BLOCK_SIZE);

		CEX::Utility::ParallelUtils::ParallelFor(0, m_processorCount, [this, &Input, InOffset, &Output, OutOffset, cnkSize, subSize](size_t i)
		{
			// offset counter by chunk size / block size
			this->Increase(m_ctrVector, m_threadVectors[i], subSize * i);
			// create random at offset position
			this->Generate(Output, (i * cnkSize), m_threadVectors[i], cnkSize);
			// xor with input at offset
			CEX::Utility::IntUtils::XORBLK(Input, InOffset + (i * cnkSize), Output, OutOffset + (i * cnkSize), cnkSize, HasIntrinsics());
		});

		// last block processing
		if (rndSize < blkSize)
		{
			size_t fnlSize = blkSize % rndSize;
			Generate(Output, rndSize, m_threadVectors[m_processorCount - 1], fnlSize);

			for (size_t i = 0; i < fnlSize; ++i)
				Output[i + OutOffset + rndSize] ^= (byte)(Input[i + InOffset + rndSize]);
		}

		// copy the last counter position to class variable
		memcpy(&m_ctrVector[0], &m_threadVectors[m_processorCount - 1][0], m_ctrVector.size() * sizeof(uint));
	}
}

void Salsa20::Transform64(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter)
{
	size_t ctr = 0;
	uint X0 = m_wrkState[ctr];
	uint X1 = m_wrkState[++ctr];
	uint X2 = m_wrkState[++ctr];
	uint X3 = m_wrkState[++ctr];
	uint X4 = m_wrkState[++ctr];
	uint X5 = m_wrkState[++ctr];
	uint X6 = m_wrkState[++ctr];
	uint X7 = m_wrkState[++ctr];
	uint X8 = Counter[0];
	uint X9 = Counter[1];
	uint X10 = m_wrkState[++ctr];
	uint X11 = m_wrkState[++ctr];
	uint X12 = m_wrkState[++ctr];
	uint X13 = m_wrkState[++ctr];
	uint X14 = m_wrkState[++ctr];
	uint X15 = m_wrkState[++ctr];

	ctr = m_rndCount;
	while (ctr != 0)
	{
		X4 ^= CEX::Utility::IntUtils::RotFL32(X0 + X12, 7);
		X8 ^= CEX::Utility::IntUtils::RotFL32(X4 + X0, 9);
		X12 ^= CEX::Utility::IntUtils::RotFL32(X8 + X4, 13);
		X0 ^= CEX::Utility::IntUtils::RotFL32(X12 + X8, 18);

		X9 ^= CEX::Utility::IntUtils::RotFL32(X5 + X1, 7);
		X13 ^= CEX::Utility::IntUtils::RotFL32(X9 + X5, 9);
		X1 ^= CEX::Utility::IntUtils::RotFL32(X13 + X9, 13);
		X5 ^= CEX::Utility::IntUtils::RotFL32(X1 + X13, 18);

		X14 ^= CEX::Utility::IntUtils::RotFL32(X10 + X6, 7);
		X2 ^= CEX::Utility::IntUtils::RotFL32(X14 + X10, 9);
		X6 ^= CEX::Utility::IntUtils::RotFL32(X2 + X14, 13);
		X10 ^= CEX::Utility::IntUtils::RotFL32(X6 + X2, 18);

		X3 ^= CEX::Utility::IntUtils::RotFL32(X15 + X11, 7);
		X7 ^= CEX::Utility::IntUtils::RotFL32(X3 + X15, 9);
		X11 ^= CEX::Utility::IntUtils::RotFL32(X7 + X3, 13);
		X15 ^= CEX::Utility::IntUtils::RotFL32(X11 + X7, 18);

		X1 ^= CEX::Utility::IntUtils::RotFL32(X0 + X3, 7);
		X2 ^= CEX::Utility::IntUtils::RotFL32(X1 + X0, 9);
		X3 ^= CEX::Utility::IntUtils::RotFL32(X2 + X1, 13);
		X0 ^= CEX::Utility::IntUtils::RotFL32(X3 + X2, 18);

		X6 ^= CEX::Utility::IntUtils::RotFL32(X5 + X4, 7);
		X7 ^= CEX::Utility::IntUtils::RotFL32(X6 + X5, 9);
		X4 ^= CEX::Utility::IntUtils::RotFL32(X7 + X6, 13);
		X5 ^= CEX::Utility::IntUtils::RotFL32(X4 + X7, 18);

		X11 ^= CEX::Utility::IntUtils::RotFL32(X10 + X9, 7);
		X8 ^= CEX::Utility::IntUtils::RotFL32(X11 + X10, 9);
		X9 ^= CEX::Utility::IntUtils::RotFL32(X8 + X11, 13);
		X10 ^= CEX::Utility::IntUtils::RotFL32(X9 + X8, 18);

		X12 ^= CEX::Utility::IntUtils::RotFL32(X15 + X14, 7);
		X13 ^= CEX::Utility::IntUtils::RotFL32(X12 + X15, 9);
		X14 ^= CEX::Utility::IntUtils::RotFL32(X13 + X12, 13);
		X15 ^= CEX::Utility::IntUtils::RotFL32(X14 + X13, 18);
		ctr -= 2;
	}

	CEX::Utility::IntUtils::Le32ToBytes(X0 + m_wrkState[ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X1 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X2 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X3 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X4 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X5 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X6 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X7 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X8 + Counter[0], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X9 + Counter[1], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X10 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X11 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X12 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X13 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X14 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X15 + m_wrkState[++ctr], Output, OutOffset);
}

void Salsa20::Transform256(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter)
{
#if defined(HAS_MINSSE) && !defined(HAS_AVX)

	size_t ctr = 0;
	std::vector<CEX::Common::UInt128> X {
		CEX::Common::UInt128(m_wrkState[ctr]),
		CEX::Common::UInt128(m_wrkState[++ctr]),
		CEX::Common::UInt128(m_wrkState[++ctr]),
		CEX::Common::UInt128(m_wrkState[++ctr]),
		CEX::Common::UInt128(m_wrkState[++ctr]),
		CEX::Common::UInt128(m_wrkState[++ctr]),
		CEX::Common::UInt128(m_wrkState[++ctr]),
		CEX::Common::UInt128(m_wrkState[++ctr]),
		CEX::Common::UInt128(Counter, 0),
		CEX::Common::UInt128(Counter, 4),
		CEX::Common::UInt128(m_wrkState[++ctr]),
		CEX::Common::UInt128(m_wrkState[++ctr]),
		CEX::Common::UInt128(m_wrkState[++ctr]),
		CEX::Common::UInt128(m_wrkState[++ctr]),
		CEX::Common::UInt128(m_wrkState[++ctr]),
		CEX::Common::UInt128(m_wrkState[++ctr]),
	};

	ctr = m_rndCount;
	while (ctr != 0)
	{
		X[4] ^= CEX::Common::UInt128::Rotl32(X[0] + X[12], 7);
		X[8] ^= CEX::Common::UInt128::Rotl32(X[4] + X[0], 9);
		X[12] ^= CEX::Common::UInt128::Rotl32(X[8] + X[4], 13);
		X[0] ^= CEX::Common::UInt128::Rotl32(X[12] + X[8], 18);

		X[9] ^= CEX::Common::UInt128::Rotl32(X[5] + X[1], 7);
		X[13] ^= CEX::Common::UInt128::Rotl32(X[9] + X[5], 9);
		X[1] ^= CEX::Common::UInt128::Rotl32(X[13] + X[9], 13);
		X[5] ^= CEX::Common::UInt128::Rotl32(X[1] + X[13], 18);

		X[14] ^= CEX::Common::UInt128::Rotl32(X[10] + X[6], 7);
		X[2] ^= CEX::Common::UInt128::Rotl32(X[14] + X[10], 9);
		X[6] ^= CEX::Common::UInt128::Rotl32(X[2] + X[14], 13);
		X[10] ^= CEX::Common::UInt128::Rotl32(X[6] + X[2], 18);

		X[3] ^= CEX::Common::UInt128::Rotl32(X[15] + X[11], 7);
		X[7] ^= CEX::Common::UInt128::Rotl32(X[3] + X[15], 9);
		X[11] ^= CEX::Common::UInt128::Rotl32(X[7] + X[3], 13);
		X[15] ^= CEX::Common::UInt128::Rotl32(X[11] + X[7], 18);

		X[1] ^= CEX::Common::UInt128::Rotl32(X[0] + X[3], 7);
		X[2] ^= CEX::Common::UInt128::Rotl32(X[1] + X[0], 9);
		X[3] ^= CEX::Common::UInt128::Rotl32(X[2] + X[1], 13);
		X[0] ^= CEX::Common::UInt128::Rotl32(X[3] + X[2], 18);

		X[6] ^= CEX::Common::UInt128::Rotl32(X[5] + X[4], 7);
		X[7] ^= CEX::Common::UInt128::Rotl32(X[6] + X[5], 9);
		X[4] ^= CEX::Common::UInt128::Rotl32(X[7] + X[6], 13);
		X[5] ^= CEX::Common::UInt128::Rotl32(X[4] + X[7], 18);

		X[11] ^= CEX::Common::UInt128::Rotl32(X[10] + X[9], 7);
		X[8] ^= CEX::Common::UInt128::Rotl32(X[11] + X[10], 9);
		X[9] ^= CEX::Common::UInt128::Rotl32(X[8] + X[11], 13);
		X[10] ^= CEX::Common::UInt128::Rotl32(X[9] + X[8], 18);

		X[12] ^= CEX::Common::UInt128::Rotl32(X[15] + X[14], 7);
		X[13] ^= CEX::Common::UInt128::Rotl32(X[12] + X[15], 9);
		X[14] ^= CEX::Common::UInt128::Rotl32(X[13] + X[12], 13);
		X[15] ^= CEX::Common::UInt128::Rotl32(X[14] + X[13], 18);
		ctr -= 2;
	}

	// last round
	X[0] += m_wrkState[ctr];
	X[1] += m_wrkState[++ctr];
	X[2] += m_wrkState[++ctr];
	X[3] += m_wrkState[++ctr];
	X[4] += m_wrkState[++ctr];
	X[5] += m_wrkState[++ctr];
	X[6] += m_wrkState[++ctr];
	X[7] += m_wrkState[++ctr];
	X[8] += CEX::Common::UInt128(Counter, 0);
	X[9] += CEX::Common::UInt128(Counter, 4);
	X[10] += m_wrkState[++ctr];
	X[11] += m_wrkState[++ctr];
	X[12] += m_wrkState[++ctr];
	X[13] += m_wrkState[++ctr];
	X[14] += m_wrkState[++ctr];
	X[15] += m_wrkState[++ctr];
	
	CEX::Common::UInt128::StoreLE256(X, 0, Output, OutOffset);

#else

	std::vector<uint> tmpCtr(2);
	tmpCtr[0] = Counter[0];
	tmpCtr[1] = Counter[4];
	Transform64(Output, OutOffset, tmpCtr);
	tmpCtr[0] = Counter[1];
	tmpCtr[1] = Counter[5];
	Transform64(Output, OutOffset + 64, tmpCtr);
	tmpCtr[0] = Counter[2];
	tmpCtr[1] = Counter[6];
	Transform64(Output, OutOffset + 128, tmpCtr);
	tmpCtr[0] = Counter[3];
	tmpCtr[1] = Counter[7];
	Transform64(Output, OutOffset + 192, tmpCtr);

#endif
}

void Salsa20::Transform512(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter)
{
#if defined(HAS_AVX)

	size_t ctr = 0;
	std::vector<CEX::Common::UInt256> X{
		CEX::Common::UInt256(m_wrkState[ctr]),
		CEX::Common::UInt256(m_wrkState[++ctr]),
		CEX::Common::UInt256(m_wrkState[++ctr]),
		CEX::Common::UInt256(m_wrkState[++ctr]),
		CEX::Common::UInt256(m_wrkState[++ctr]),
		CEX::Common::UInt256(m_wrkState[++ctr]),
		CEX::Common::UInt256(m_wrkState[++ctr]),
		CEX::Common::UInt256(m_wrkState[++ctr]),
		CEX::Common::UInt256(Counter, 0),
		CEX::Common::UInt256(Counter, 8),
		CEX::Common::UInt256(m_wrkState[++ctr]),
		CEX::Common::UInt256(m_wrkState[++ctr]),
		CEX::Common::UInt256(m_wrkState[++ctr]),
		CEX::Common::UInt256(m_wrkState[++ctr]),
		CEX::Common::UInt256(m_wrkState[++ctr]),
		CEX::Common::UInt256(m_wrkState[++ctr]),
	};

	ctr = m_rndCount;
	while (ctr != 0)
	{
		X[4] ^= CEX::Common::UInt256::Rotl32(X[0] + X[12], 7);
		X[8] ^= CEX::Common::UInt256::Rotl32(X[4] + X[0], 9);
		X[12] ^= CEX::Common::UInt256::Rotl32(X[8] + X[4], 13);
		X[0] ^= CEX::Common::UInt256::Rotl32(X[12] + X[8], 18);

		X[9] ^= CEX::Common::UInt256::Rotl32(X[5] + X[1], 7);
		X[13] ^= CEX::Common::UInt256::Rotl32(X[9] + X[5], 9);
		X[1] ^= CEX::Common::UInt256::Rotl32(X[13] + X[9], 13);
		X[5] ^= CEX::Common::UInt256::Rotl32(X[1] + X[13], 18);

		X[14] ^= CEX::Common::UInt256::Rotl32(X[10] + X[6], 7);
		X[2] ^= CEX::Common::UInt256::Rotl32(X[14] + X[10], 9);
		X[6] ^= CEX::Common::UInt256::Rotl32(X[2] + X[14], 13);
		X[10] ^= CEX::Common::UInt256::Rotl32(X[6] + X[2], 18);

		X[3] ^= CEX::Common::UInt256::Rotl32(X[15] + X[11], 7);
		X[7] ^= CEX::Common::UInt256::Rotl32(X[3] + X[15], 9);
		X[11] ^= CEX::Common::UInt256::Rotl32(X[7] + X[3], 13);
		X[15] ^= CEX::Common::UInt256::Rotl32(X[11] + X[7], 18);

		X[1] ^= CEX::Common::UInt256::Rotl32(X[0] + X[3], 7);
		X[2] ^= CEX::Common::UInt256::Rotl32(X[1] + X[0], 9);
		X[3] ^= CEX::Common::UInt256::Rotl32(X[2] + X[1], 13);
		X[0] ^= CEX::Common::UInt256::Rotl32(X[3] + X[2], 18);

		X[6] ^= CEX::Common::UInt256::Rotl32(X[5] + X[4], 7);
		X[7] ^= CEX::Common::UInt256::Rotl32(X[6] + X[5], 9);
		X[4] ^= CEX::Common::UInt256::Rotl32(X[7] + X[6], 13);
		X[5] ^= CEX::Common::UInt256::Rotl32(X[4] + X[7], 18);

		X[11] ^= CEX::Common::UInt256::Rotl32(X[10] + X[9], 7);
		X[8] ^= CEX::Common::UInt256::Rotl32(X[11] + X[10], 9);
		X[9] ^= CEX::Common::UInt256::Rotl32(X[8] + X[11], 13);
		X[10] ^= CEX::Common::UInt256::Rotl32(X[9] + X[8], 18);

		X[12] ^= CEX::Common::UInt256::Rotl32(X[15] + X[14], 7);
		X[13] ^= CEX::Common::UInt256::Rotl32(X[12] + X[15], 9);
		X[14] ^= CEX::Common::UInt256::Rotl32(X[13] + X[12], 13);
		X[15] ^= CEX::Common::UInt256::Rotl32(X[14] + X[13], 18);
		ctr -= 2;
	}

	// last round
	X[0] += m_wrkState[ctr];
	X[1] += m_wrkState[++ctr];
	X[2] += m_wrkState[++ctr];
	X[3] += m_wrkState[++ctr];
	X[4] += m_wrkState[++ctr];
	X[5] += m_wrkState[++ctr];
	X[6] += m_wrkState[++ctr];
	X[7] += m_wrkState[++ctr];
	X[8] += CEX::Common::UInt256(Counter, 0);
	X[9] += CEX::Common::UInt256(Counter, 8);
	X[10] += m_wrkState[++ctr];
	X[11] += m_wrkState[++ctr];
	X[12] += m_wrkState[++ctr];
	X[13] += m_wrkState[++ctr];
	X[14] += m_wrkState[++ctr];
	X[15] += m_wrkState[++ctr];

	CEX::Common::UInt256::StoreLE512(X, 0, Output, OutOffset);

#else

	std::vector<uint> tmpCtr(2);
	tmpCtr[0] = Counter[0];
	tmpCtr[1] = Counter[8];
	Transform64(Output, OutOffset, tmpCtr);
	tmpCtr[0] = Counter[1];
	tmpCtr[1] = Counter[9];
	Transform64(Output, OutOffset + 64, tmpCtr);
	tmpCtr[0] = Counter[2];
	tmpCtr[1] = Counter[10];
	Transform64(Output, OutOffset + 128, tmpCtr);
	tmpCtr[0] = Counter[3];
	tmpCtr[1] = Counter[11];
	Transform64(Output, OutOffset + 192, tmpCtr);
	tmpCtr[0] = Counter[4];
	tmpCtr[1] = Counter[12];
	Transform64(Output, OutOffset + 256, tmpCtr);
	tmpCtr[0] = Counter[5];
	tmpCtr[1] = Counter[13];
	Transform64(Output, OutOffset + 320, tmpCtr);
	tmpCtr[0] = Counter[6];
	tmpCtr[1] = Counter[14];
	Transform64(Output, OutOffset + 384, tmpCtr);
	tmpCtr[0] = Counter[7];
	tmpCtr[1] = Counter[15];
	Transform64(Output, OutOffset + 448, tmpCtr);

#endif
}

void Salsa20::SetScope()
{
	m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;
	if (m_processorCount > 1)
		m_isParallel = true;

	if (m_isParallel)
	{
		m_parallelMinimumSize = m_processorCount * BLOCK_SIZE;

		if (m_hasAVX)
			m_parallelMinimumSize *= 8;
		else if (m_hasIntrinsics)
			m_parallelMinimumSize *= 4;

		m_parallelBlockSize = m_parallelMinimumSize * 10;

		if (m_threadVectors.size() != m_processorCount)
			m_threadVectors.resize(m_processorCount);
		for (size_t i = 0; i < m_processorCount; ++i)
			m_threadVectors[i].resize(VECTOR_SIZE / sizeof(uint));
	}
}

NAMESPACE_STREAMEND