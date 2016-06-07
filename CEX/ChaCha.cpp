#include "ChaCha.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_STREAM

void ChaCha::Destroy()
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

void ChaCha::Initialize(const CEX::Common::KeyParams &KeyParam)
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

void ChaCha::Reset()
{
	m_ctrVector[0] = 0;
	m_ctrVector[1] = 0;
}

void ChaCha::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	ProcessBlock(Input, 0, Output, 0, Input.size());
}

void ChaCha::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	ProcessBlock(Input, InOffset, Output, OutOffset, m_isParallel ? m_parallelBlockSize : BLOCK_SIZE);
}

void ChaCha::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	ProcessBlock(Input, InOffset, Output, OutOffset, Length);
}

// ** Key Schedule ** //

void ChaCha::SetKey(const std::vector<byte> &Key, const std::vector<byte> &Iv)
{
	if (Key.size() == 32)
	{
		m_wrkState[0] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 0);
		m_wrkState[1] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 4);
		m_wrkState[2] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 8);
		m_wrkState[3] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 12);
		m_wrkState[4] = CEX::Utility::IntUtils::BytesToLe32(Key, 0);
		m_wrkState[5] = CEX::Utility::IntUtils::BytesToLe32(Key, 4);
		m_wrkState[6] = CEX::Utility::IntUtils::BytesToLe32(Key, 8);
		m_wrkState[7] = CEX::Utility::IntUtils::BytesToLe32(Key, 12);
		m_wrkState[8] = CEX::Utility::IntUtils::BytesToLe32(Key, 16);
		m_wrkState[9] = CEX::Utility::IntUtils::BytesToLe32(Key, 20);
		m_wrkState[10] = CEX::Utility::IntUtils::BytesToLe32(Key, 24);
		m_wrkState[11] = CEX::Utility::IntUtils::BytesToLe32(Key, 28);
		m_wrkState[12] = CEX::Utility::IntUtils::BytesToLe32(Iv, 0);
		m_wrkState[13] = CEX::Utility::IntUtils::BytesToLe32(Iv, 4);

	}
	else
	{
		m_wrkState[0] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 0);
		m_wrkState[1] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 4);
		m_wrkState[2] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 8);
		m_wrkState[3] = CEX::Utility::IntUtils::BytesToLe32(m_dstCode, 12);
		m_wrkState[4] = CEX::Utility::IntUtils::BytesToLe32(Key, 0);
		m_wrkState[5] = CEX::Utility::IntUtils::BytesToLe32(Key, 4);
		m_wrkState[6] = CEX::Utility::IntUtils::BytesToLe32(Key, 8);
		m_wrkState[7] = CEX::Utility::IntUtils::BytesToLe32(Key, 12);
		m_wrkState[8] = CEX::Utility::IntUtils::BytesToLe32(Key, 0);
		m_wrkState[9] = CEX::Utility::IntUtils::BytesToLe32(Key, 4);
		m_wrkState[10] = CEX::Utility::IntUtils::BytesToLe32(Key, 8);
		m_wrkState[11] = CEX::Utility::IntUtils::BytesToLe32(Key, 12);
		m_wrkState[12] = CEX::Utility::IntUtils::BytesToLe32(Iv, 0);
		m_wrkState[13] = CEX::Utility::IntUtils::BytesToLe32(Iv, 4);
	}
}

// ** Processing ** //

void ChaCha::Increase(const std::vector<uint> &Counter, const size_t Size, std::vector<uint> &Buffer)
{
	Buffer = Counter;

	for (size_t i = 0; i < Size; i++)
		Increment(Buffer);
}

void ChaCha::Increment(std::vector<uint> &Counter)
{
	if (++Counter[0] == 0)
		++Counter[1];
}

void ChaCha::Generate(const size_t Size, std::vector<uint> &Counter, std::vector<byte> &Output, const size_t OutOffset)
{
	size_t aln = Size - (Size % BLOCK_SIZE);
	size_t ctr = 0;

	while (ctr != aln)
	{
		ChaChaCore(Output, OutOffset + ctr, Counter);
		Increment(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Size)
	{
		std::vector<byte> outputBlock(BLOCK_SIZE, 0);
		ChaChaCore(outputBlock, 0, Counter);
		size_t fnlSize = Size % BLOCK_SIZE;
		memcpy(&Output[OutOffset + (Size - fnlSize)], &outputBlock[0], fnlSize);
		Increment(Counter);
	}
}

uint ChaCha::GetProcessorCount()
{
	return CEX::Utility::ParallelUtils::ProcessorCount();
}

void ChaCha::ProcessBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
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
		if (sze != OutOffset + blkSize)
		{
			for (size_t i = sze; i < Output.size(); ++i)
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
		memcpy(&m_ctrVector[0], &m_threadVectors[m_processorCount - 1][0], m_ctrVector.size() * sizeof(uint));
	}
}

void ChaCha::ChaChaCore(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter)
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
	uint X8 = m_wrkState[++ctr];
	uint X9 = m_wrkState[++ctr];
	uint X10 = m_wrkState[++ctr];
	uint X11 = m_wrkState[++ctr];
	uint X12 = Counter[0];
	uint X13 = Counter[1];
	uint X14 = m_wrkState[++ctr];
	uint X15 = m_wrkState[++ctr];

	ctr = m_rndCount;
	while (ctr != 0)
	{
		X0 += X4; 
		X12 = CEX::Utility::IntUtils::RotateFixLeft(X12 ^ X0, 16);
		X8 += X12;
		X4 = CEX::Utility::IntUtils::RotateFixLeft(X4 ^ X8, 12);
		X0 += X4; 
		X12 = CEX::Utility::IntUtils::RotateFixLeft(X12 ^ X0, 8);
		X8 += X12; 
		X4 = CEX::Utility::IntUtils::RotateFixLeft(X4 ^ X8, 7);
		X1 += X5; 
		X13 = CEX::Utility::IntUtils::RotateFixLeft(X13 ^ X1, 16);
		X9 += X13; 
		X5 = CEX::Utility::IntUtils::RotateFixLeft(X5 ^ X9, 12);
		X1 += X5; 
		X13 = CEX::Utility::IntUtils::RotateFixLeft(X13 ^ X1, 8);
		X9 += X13; 
		X5 = CEX::Utility::IntUtils::RotateFixLeft(X5 ^ X9, 7);
		X2 += X6; 
		X14 = CEX::Utility::IntUtils::RotateFixLeft(X14 ^ X2, 16);
		X10 += X14; 
		X6 = CEX::Utility::IntUtils::RotateFixLeft(X6 ^ X10, 12);
		X2 += X6; 
		X14 = CEX::Utility::IntUtils::RotateFixLeft(X14 ^ X2, 8);
		X10 += X14; 
		X6 = CEX::Utility::IntUtils::RotateFixLeft(X6 ^ X10, 7);
		X3 += X7; 
		X15 = CEX::Utility::IntUtils::RotateFixLeft(X15 ^ X3, 16);
		X11 += X15; 
		X7 = CEX::Utility::IntUtils::RotateFixLeft(X7 ^ X11, 12);
		X3 += X7; 
		X15 = CEX::Utility::IntUtils::RotateFixLeft(X15 ^ X3, 8);
		X11 += X15; 
		X7 = CEX::Utility::IntUtils::RotateFixLeft(X7 ^ X11, 7);
		X0 += X5; 
		X15 = CEX::Utility::IntUtils::RotateFixLeft(X15 ^ X0, 16);
		X10 += X15; 
		X5 = CEX::Utility::IntUtils::RotateFixLeft(X5 ^ X10, 12);
		X0 += X5; 
		X15 = CEX::Utility::IntUtils::RotateFixLeft(X15 ^ X0, 8);
		X10 += X15; 
		X5 = CEX::Utility::IntUtils::RotateFixLeft(X5 ^ X10, 7);
		X1 += X6; 
		X12 = CEX::Utility::IntUtils::RotateFixLeft(X12 ^ X1, 16);
		X11 += X12; 
		X6 = CEX::Utility::IntUtils::RotateFixLeft(X6 ^ X11, 12);
		X1 += X6; 
		X12 = CEX::Utility::IntUtils::RotateFixLeft(X12 ^ X1, 8);
		X11 += X12; 
		X6 = CEX::Utility::IntUtils::RotateFixLeft(X6 ^ X11, 7);
		X2 += X7; 
		X13 = CEX::Utility::IntUtils::RotateFixLeft(X13 ^ X2, 16);
		X8 += X13; 
		X7 = CEX::Utility::IntUtils::RotateFixLeft(X7 ^ X8, 12);
		X2 += X7; 
		X13 = CEX::Utility::IntUtils::RotateFixLeft(X13 ^ X2, 8);
		X8 += X13; 
		X7 = CEX::Utility::IntUtils::RotateFixLeft(X7 ^ X8, 7);
		X3 += X4; 
		X14 = CEX::Utility::IntUtils::RotateFixLeft(X14 ^ X3, 16);
		X9 += X14; 
		X4 = CEX::Utility::IntUtils::RotateFixLeft(X4 ^ X9, 12);
		X3 += X4; 
		X14 = CEX::Utility::IntUtils::RotateFixLeft(X14 ^ X3, 8);
		X9 += X14; 
		X4 = CEX::Utility::IntUtils::RotateFixLeft(X4 ^ X9, 7);
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
	CEX::Utility::IntUtils::Le32ToBytes(X8 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X9 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X10 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X11 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X12 + Counter[0], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X13 + Counter[1], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X14 + m_wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X15 + m_wrkState[++ctr], Output, OutOffset);
}

void ChaCha::SetScope()
{
	m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;
	if (m_processorCount > 1)
		m_isParallel = true;
}

NAMESPACE_STREAMEND