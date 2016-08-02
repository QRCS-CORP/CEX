#include "SP20Drbg.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_GENERATOR

void SP20Drbg::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isInitialized = false;
		m_processorCount = 0;
		m_isParallel = false;
		m_parallelBlockSize = 0;
		m_rndCount = 0;

		CEX::Utility::IntUtils::ClearVector(m_ctrVector);
		CEX::Utility::IntUtils::ClearVector(m_dstCode);
		CEX::Utility::IntUtils::ClearVector(m_legalRounds);
		CEX::Utility::IntUtils::ClearVector(m_threadVectors);
		CEX::Utility::IntUtils::ClearVector(m_wrkState);

		m_isDestroyed = true;
	}
}

size_t SP20Drbg::Generate(std::vector<byte> &Output)
{
	Transform(Output, 0);
	return Output.size();
}

size_t SP20Drbg::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("SP20Drbg:Generate", "Output buffer too small!");
#endif

	Transform(Output, OutOffset);
	return Size;
}

void SP20Drbg::Initialize(const std::vector<byte> &Ikm)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Ikm.size() != m_legalKeySizes[0] + VECTOR_SIZE && Ikm.size() != m_legalKeySizes[1] + VECTOR_SIZE)
		throw CryptoGeneratorException("SP20Drbg:Initialize", "Key material size is too small; must be exactly 24 (128 bit key) or 40 bytes (256 bit key)!");
#endif

	std::string info;
	if (Ikm.size() == 24)
		info = "expand 16-byte k";
	else
		info = "expand 32-byte k";

	m_dstCode.reserve(info.size());
	for (size_t i = 0; i < info.size(); ++i)
		m_dstCode.push_back(info[i]);

	std::vector<byte> iv(VECTOR_SIZE);
	memcpy(&iv[0], &Ikm[0], VECTOR_SIZE);
	size_t keyLen = Ikm.size() - VECTOR_SIZE;
	std::vector<byte> key(keyLen);
	memcpy(&key[0], &Ikm[VECTOR_SIZE], keyLen);
	SetKey(key, iv);
	m_isInitialized = true;
}

void SP20Drbg::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm)
{
	std::vector<byte> key(Salt.size() + Ikm.size());
	memcpy(&key[0], &Salt[0], Salt.size());
	memcpy(&key[Salt.size()], &Ikm[0], Ikm.size());
	Initialize(key);
}

void SP20Drbg::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Nonce)
{
	std::vector<byte> key(Salt.size() + Ikm.size() + Nonce.size());
	memcpy(&key[0], &Salt[0], Salt.size());
	memcpy(&key[Salt.size()], &Ikm[0], Ikm.size());
	memcpy(&key[Salt.size() + Ikm.size()], &Nonce[0], Nonce.size());
	Initialize(key);
}

void SP20Drbg::Update(const std::vector<byte> &Salt)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Salt.size() == 0)
		throw CryptoGeneratorException("SP20Drbg:Update", "Salt is too small!");
#endif

	if (Salt.size() == m_legalKeySizes[0] + VECTOR_SIZE || Salt.size() == m_legalKeySizes[1] + VECTOR_SIZE)
		Initialize(Salt);
	else if (Salt.size() == VECTOR_SIZE)
		memcpy(&m_ctrVector[0], &Salt[0], m_ctrVector.size());
#if defined(CPPEXCEPTIONS_ENABLED)
	else
		throw CryptoGeneratorException("SP20Drbg:Update", "Salt must be either 40 bytes; (key and vector), or 8 bytes; (vector only) in length!");
#endif
}

// *** Private *** //

void SP20Drbg::Generate(const size_t Length, std::vector<uint> &Counter, std::vector<byte> &Output, const size_t OutOffset)
{
	size_t aln = Length - (Length % BLOCK_SIZE);
	size_t ctr = 0;

	while (ctr != aln)
	{
		SalsaCore(Output, OutOffset + ctr, Counter);
		Increment(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
		std::vector<byte> outputBlock(BLOCK_SIZE, 0);
		SalsaCore(outputBlock, 0, Counter);
		size_t fnlSize = Length % BLOCK_SIZE;
		memcpy(&Output[OutOffset + (Length - fnlSize)], &outputBlock[0], fnlSize);
		Increment(Counter);
	}
}

void SP20Drbg::Increase(const std::vector<uint> &Counter, const size_t Size, std::vector<uint> &Vector)
{
	Vector = Counter;

	for (size_t i = 0; i < Size; i++)
		Increment(Vector);
}

void SP20Drbg::Increment(std::vector<uint> &Counter)
{
	if (++Counter[0] == 0)
		++Counter[1];
}

void SP20Drbg::SalsaCore(std::vector<byte> &Output, size_t OutOffset, const std::vector<uint> &Counter)
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
		X4 ^= CEX::Utility::IntUtils::RotL32(X0 + X12, 7);
		X8 ^= CEX::Utility::IntUtils::RotL32(X4 + X0, 9);
		X12 ^= CEX::Utility::IntUtils::RotL32(X8 + X4, 13);
		X0 ^= CEX::Utility::IntUtils::RotL32(X12 + X8, 18);
		X9 ^= CEX::Utility::IntUtils::RotL32(X5 + X1, 7);
		X13 ^= CEX::Utility::IntUtils::RotL32(X9 + X5, 9);
		X1 ^= CEX::Utility::IntUtils::RotL32(X13 + X9, 13);
		X5 ^= CEX::Utility::IntUtils::RotL32(X1 + X13, 18);
		X14 ^= CEX::Utility::IntUtils::RotL32(X10 + X6, 7);
		X2 ^= CEX::Utility::IntUtils::RotL32(X14 + X10, 9);
		X6 ^= CEX::Utility::IntUtils::RotL32(X2 + X14, 13);
		X10 ^= CEX::Utility::IntUtils::RotL32(X6 + X2, 18);
		X3 ^= CEX::Utility::IntUtils::RotL32(X15 + X11, 7);
		X7 ^= CEX::Utility::IntUtils::RotL32(X3 + X15, 9);
		X11 ^= CEX::Utility::IntUtils::RotL32(X7 + X3, 13);
		X15 ^= CEX::Utility::IntUtils::RotL32(X11 + X7, 18);
		X1 ^= CEX::Utility::IntUtils::RotL32(X0 + X3, 7);
		X2 ^= CEX::Utility::IntUtils::RotL32(X1 + X0, 9);
		X3 ^= CEX::Utility::IntUtils::RotL32(X2 + X1, 13);
		X0 ^= CEX::Utility::IntUtils::RotL32(X3 + X2, 18);
		X6 ^= CEX::Utility::IntUtils::RotL32(X5 + X4, 7);
		X7 ^= CEX::Utility::IntUtils::RotL32(X6 + X5, 9);
		X4 ^= CEX::Utility::IntUtils::RotL32(X7 + X6, 13);
		X5 ^= CEX::Utility::IntUtils::RotL32(X4 + X7, 18);
		X11 ^= CEX::Utility::IntUtils::RotL32(X10 + X9, 7);
		X8 ^= CEX::Utility::IntUtils::RotL32(X11 + X10, 9);
		X9 ^= CEX::Utility::IntUtils::RotL32(X8 + X11, 13);
		X10 ^= CEX::Utility::IntUtils::RotL32(X9 + X8, 18);
		X12 ^= CEX::Utility::IntUtils::RotL32(X15 + X14, 7);
		X13 ^= CEX::Utility::IntUtils::RotL32(X12 + X15, 9);
		X14 ^= CEX::Utility::IntUtils::RotL32(X13 + X12, 13);
		X15 ^= CEX::Utility::IntUtils::RotL32(X14 + X13, 18);
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

void SP20Drbg::SetKey(const std::vector<byte> &Key, const std::vector<byte> &Iv)
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

void SP20Drbg::SetScope()
{
	m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;
	if (m_processorCount > 1)
		m_isParallel = true;
}

void SP20Drbg::Transform(std::vector<byte> &Output, size_t OutOffset)
{
	size_t outSize = Output.size() - OutOffset;

	if (!m_isParallel || outSize < m_parallelBlockSize)
	{
		// generate random
		Generate(outSize, m_ctrVector, Output, OutOffset);
	}
	else
	{
		// parallel CTR processing //
		size_t cnkSize = (outSize / BLOCK_SIZE / m_processorCount) * BLOCK_SIZE;
		size_t rndSize = cnkSize * m_processorCount;
		size_t subSize = (cnkSize / BLOCK_SIZE);
		// create jagged array of 'sub counters'
		m_threadVectors.resize(m_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, m_processorCount, [this, &Output, cnkSize, rndSize, subSize, OutOffset](size_t i)
		{
			std::vector<uint> &iv = m_threadVectors[i];
			// offset counter by chunk size / block size
			this->Increase(m_ctrVector, subSize * i, iv);
			// create random at offset position
			this->Generate(cnkSize, iv, Output, OutOffset + (i * cnkSize));
		});

		// last block processing
		if (rndSize < outSize)
		{
			size_t fnlSize = outSize % rndSize;
			Generate(fnlSize, m_threadVectors[m_processorCount - 1], Output, OutOffset + rndSize);
		}

		// copy the last counter position to class variable
		memcpy(&m_ctrVector[0], &m_threadVectors[m_processorCount - 1][0], m_ctrVector.size() * sizeof(uint));
	}
}

NAMESPACE_GENERATOREND