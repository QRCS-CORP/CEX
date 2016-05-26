#include "Salsa20.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_STREAM

void Salsa20::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isInitialized = false;
		m_processorCount = 0;
		m_isParallel = false;
		m_parallelBlockSize = 0;
		m_rndCount = 0;

		CEX::Utility::IntUtils::ClearVector(m_ctrVector);
		CEX::Utility::IntUtils::ClearVector(m_wrkState);
		CEX::Utility::IntUtils::ClearVector(m_dstCode);
		CEX::Utility::IntUtils::ClearVector(m_threadVectors);
	}
}

void Salsa20::Initialize(const CEX::Common::KeyParams &KeyParam)
{
	if (KeyParam.IV().size() != 8)
		throw CryptoSymmetricCipherException("Salsa20:Initialize", "Requires exactly 8 bytes of IV!");
	if (KeyParam.Key().size() != 16 && KeyParam.Key().size() != 32)
		throw CryptoSymmetricCipherException("Salsa20:Initialize", "Key must be 16 or 32 bytes!");

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

void Salsa20::Increase(const std::vector<uint> &Counter, const size_t Size, std::vector<uint> &Vector)
{
	Vector = Counter;

	for (size_t i = 0; i < Size; i++)
		Increment(Vector);
}

void Salsa20::Increment(std::vector<uint> &Counter)
{
	if (++Counter[0] == 0)
		++Counter[1];
}

void Salsa20::Generate(const size_t Size, std::vector<uint> &Counter, std::vector<byte> &Output, const size_t OutOffset)
{
	size_t aln = Size - (Size % BLOCK_SIZE);
	size_t ctr = 0;

	while (ctr != aln)
	{
		SalsaCore(Output, OutOffset + ctr, Counter);
		Increment(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Size)
	{
		std::vector<byte> outputBlock(BLOCK_SIZE, 0);
		SalsaCore(outputBlock, 0, Counter);
		int fnlSize = Size % BLOCK_SIZE;
		memcpy(&Output[OutOffset + (Size - fnlSize)], &outputBlock[0], fnlSize);
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

	if (!m_isParallel || blkSize < m_parallelBlockSize)
	{
		// generate random
		Generate(blkSize, m_ctrVector, Output, OutOffset);
		// output is input xor with random
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
		size_t cnkSize = (blkSize / BLOCK_SIZE / m_processorCount) * BLOCK_SIZE;
		size_t rndSize = cnkSize * m_processorCount;
		size_t subSize = (cnkSize / BLOCK_SIZE);

		// create jagged array of 'sub counters'
		m_threadVectors.resize(m_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, m_processorCount, [this, &Input, InOffset, &Output, OutOffset, cnkSize, rndSize, subSize](size_t i)
		{
			std::vector<uint> &Vec = m_threadVectors[i];
			// offset counter by chunk size / block size
			this->Increase(m_ctrVector, subSize * i, Vec);
			// create random at offset position
			this->Generate(cnkSize, Vec, Output, (i * cnkSize));
			// xor with input at offset
			CEX::Utility::IntUtils::XORBLK(Input, InOffset + (i * cnkSize), Output, OutOffset + (i * cnkSize), cnkSize);
		});

		// last block processing
		if (rndSize < blkSize)
		{
			size_t fnlSize = blkSize % rndSize;
			Generate(fnlSize, m_threadVectors[m_processorCount - 1], Output, rndSize);

			for (size_t i = 0; i < fnlSize; ++i)
				Output[i + OutOffset + rndSize] ^= (byte)(Input[i + InOffset + rndSize]);
		}

		// copy the last counter position to class variable
		size_t x = sizeof(m_ctrVector);
		memcpy(&m_ctrVector[0], &m_threadVectors[m_processorCount - 1][0], m_ctrVector.size() * sizeof(uint));
	}
}

void Salsa20::SalsaCore(std::vector<byte> &Output, size_t OutOffset, const std::vector<uint> &Counter)
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
		X4 ^= CEX::Utility::IntUtils::RotlFixed(X0 + X12, 7);
		X8 ^= CEX::Utility::IntUtils::RotlFixed(X4 + X0, 9);
		X12 ^= CEX::Utility::IntUtils::RotlFixed(X8 + X4, 13);
		X0 ^= CEX::Utility::IntUtils::RotlFixed(X12 + X8, 18);
		X9 ^= CEX::Utility::IntUtils::RotlFixed(X5 + X1, 7);
		X13 ^= CEX::Utility::IntUtils::RotlFixed(X9 + X5, 9);
		X1 ^= CEX::Utility::IntUtils::RotlFixed(X13 + X9, 13);
		X5 ^= CEX::Utility::IntUtils::RotlFixed(X1 + X13, 18);
		X14 ^= CEX::Utility::IntUtils::RotlFixed(X10 + X6, 7);
		X2 ^= CEX::Utility::IntUtils::RotlFixed(X14 + X10, 9);
		X6 ^= CEX::Utility::IntUtils::RotlFixed(X2 + X14, 13);
		X10 ^= CEX::Utility::IntUtils::RotlFixed(X6 + X2, 18);
		X3 ^= CEX::Utility::IntUtils::RotlFixed(X15 + X11, 7);
		X7 ^= CEX::Utility::IntUtils::RotlFixed(X3 + X15, 9);
		X11 ^= CEX::Utility::IntUtils::RotlFixed(X7 + X3, 13);
		X15 ^= CEX::Utility::IntUtils::RotlFixed(X11 + X7, 18);
		X1 ^= CEX::Utility::IntUtils::RotlFixed(X0 + X3, 7);
		X2 ^= CEX::Utility::IntUtils::RotlFixed(X1 + X0, 9);
		X3 ^= CEX::Utility::IntUtils::RotlFixed(X2 + X1, 13);
		X0 ^= CEX::Utility::IntUtils::RotlFixed(X3 + X2, 18);
		X6 ^= CEX::Utility::IntUtils::RotlFixed(X5 + X4, 7);
		X7 ^= CEX::Utility::IntUtils::RotlFixed(X6 + X5, 9);
		X4 ^= CEX::Utility::IntUtils::RotlFixed(X7 + X6, 13);
		X5 ^= CEX::Utility::IntUtils::RotlFixed(X4 + X7, 18);
		X11 ^= CEX::Utility::IntUtils::RotlFixed(X10 + X9, 7);
		X8 ^= CEX::Utility::IntUtils::RotlFixed(X11 + X10, 9);
		X9 ^= CEX::Utility::IntUtils::RotlFixed(X8 + X11, 13);
		X10 ^= CEX::Utility::IntUtils::RotlFixed(X9 + X8, 18);
		X12 ^= CEX::Utility::IntUtils::RotlFixed(X15 + X14, 7);
		X13 ^= CEX::Utility::IntUtils::RotlFixed(X12 + X15, 9);
		X14 ^= CEX::Utility::IntUtils::RotlFixed(X13 + X12, 13);
		X15 ^= CEX::Utility::IntUtils::RotlFixed(X14 + X13, 18);
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

void Salsa20::SetScope()
{
	m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;
	if (m_processorCount > 1)
		m_isParallel = true;
}

NAMESPACE_STREAMEND