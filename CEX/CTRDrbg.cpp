#include "CTRDrbg.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "KeyParams.h"
#include "ParallelUtils.h"

NAMESPACE_GENERATOR

using CEX::Common::CpuDetect;
using CEX::Utility::IntUtils;
using CEX::Common::KeyParams;
using CEX::Utility::ParallelUtils;

void CTRDrbg::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_hasAVX = false;
		m_hasSSE = false;
		m_isEncryption = false;
		m_isInitialized = false;
		m_processorCount = 0;
		m_isParallel = false;
		m_keySize = 0;
		m_parallelBlockSize = 0;

		IntUtils::ClearVector(m_ctrVector);
		IntUtils::ClearVector(m_thdVectors);
	}
}

size_t CTRDrbg::Generate(std::vector<byte> &Output)
{
	Transform(Output, 0);
	
	return Output.size();
}

size_t CTRDrbg::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("CTRDrbg:Generate", "Output buffer too small!");
#endif
	Transform(Output, OutOffset);

	return Size;
}

void CTRDrbg::Initialize(const std::vector<byte> &Ikm)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Ikm.size() != m_keySize + m_blockSize)
		throw CryptoGeneratorException("CTRDrbg:Initialize", "Salt size is too small; must be key size plus the blocksize!");
#endif

	memcpy(&m_ctrVector[0], &Ikm[0], m_blockSize);
	size_t keyLen = Ikm.size() - m_blockSize;
	std::vector<byte> key(keyLen);
	memcpy(&key[0], &Ikm[m_blockSize], keyLen);

	m_blockCipher->Initialize(true, KeyParams(key));
	m_isInitialized = true;
}

void CTRDrbg::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm)
{
	std::vector<byte> key(Salt.size() + Ikm.size());
	if (Salt.size() > 0)
		memcpy(&key[0], &Salt[0], Salt.size());
	if (Ikm.size() > 0)
		memcpy(&key[Salt.size()], &Ikm[0], Ikm.size());

	Initialize(key);
}

void CTRDrbg::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Nonce)
{
	std::vector<byte> key(Salt.size() + Ikm.size() + Nonce.size());
	if (Salt.size() > 0)
		memcpy(&key[0], &Salt[0], Salt.size());
	if (Ikm.size() > 0)
		memcpy(&key[Salt.size()], &Ikm[0], Ikm.size());
	if (Nonce.size() > 0)
		memcpy(&key[Salt.size() + Ikm.size()], &Nonce[0], Nonce.size());

	Initialize(key);
}

void CTRDrbg::ParallelMaxDegree(size_t Degree)
{
	//ToDo
}

void CTRDrbg::Update(const std::vector<byte> &Salt)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Salt.size() == 0)
		throw CryptoGeneratorException("CTRDrbg:Update", "Salt is too small!");
#endif

	if (Salt.size() >= m_keySize)
		Initialize(Salt);
	else if (Salt.size() >= m_blockSize)
		memcpy(&m_ctrVector[0], &Salt[0], m_ctrVector.size());
}

//~~~Private~~~//

void CTRDrbg::Detect()
{
	try
	{
		CpuDetect detect;
		m_hasSSE = detect.HasMinIntrinsics();
		m_hasAVX = detect.HasAVX();
		m_parallelBlockSize = detect.L1CacheSize * 1000;
	}
	catch (...)
	{
#if defined(DEBUGASSERT_ENABLED)
		assert("CpuDetect not compatable!");
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
		throw CryptoGeneratorException("CTRDrbg:Detect", "CpuDetect not compatable!");
#endif
	}
}

void CTRDrbg::Generate(std::vector<byte> &Output, const size_t OutOffset, const size_t Length, std::vector<byte> &Counter)
{
	size_t ctr = 0;
	const size_t BALN = Length - (Length % m_blockSize);
	const size_t BLK4 = 4 * m_blockSize;

	if (m_hasAVX && Length >= 2 * BLK4)
	{
		const size_t BLK8 = 8 * m_blockSize;
		size_t paln = Length - (Length % BLK8);
		std::vector<byte> ctrBlk(BLK8);

		// stagger counters and process 8 blocks with avx
		while (ctr != paln)
		{
			memcpy(&ctrBlk[0], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[16], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[32], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[48], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[64], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[80], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[96], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[112], &Counter[0], Counter.size());
			Increment(Counter);
			m_blockCipher->Transform128(ctrBlk, 0, Output, OutOffset + ctr);
			ctr += BLK8;
		}
	}
	else if (m_hasSSE && Length >= BLK4)
	{
		size_t paln = Length - (Length % BLK4);
		std::vector<byte> ctrBlk(BLK4);

		// 4 blocks with sse
		while (ctr != paln)
		{
			memcpy(&ctrBlk[0], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[16], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[32], &Counter[0], Counter.size());
			Increment(Counter);
			memcpy(&ctrBlk[48], &Counter[0], Counter.size());
			Increment(Counter);
			m_blockCipher->Transform64(ctrBlk, 0, Output, OutOffset + ctr);
			ctr += BLK4;
		}
	}

	while (ctr != BALN)
	{
		m_blockCipher->EncryptBlock(Counter, 0, Output, OutOffset + ctr);
		Increment(Counter);
		ctr += m_blockSize;
	}

	if (ctr != Length)
	{
		std::vector<byte> outputBlock(m_blockSize, 0);
		m_blockCipher->EncryptBlock(Counter, outputBlock);
		size_t fnlSize = Length % m_blockSize;
		memcpy(&Output[OutOffset + (Length - fnlSize)], &outputBlock[0], fnlSize);
		Increment(Counter);
	}
}

void CTRDrbg::Increment(std::vector<byte> &Counter)
{
	size_t i = Counter.size();
	while (--i >= 0 && ++Counter[i] == 0) {}
}

void CTRDrbg::Increase(const std::vector<byte> &Counter, const size_t Size, std::vector<byte> &Buffer)
{
	Buffer.resize(Counter.size(), 0);

	size_t carry = 0;
	size_t offset = Buffer.size() - 1;

	const int cntSize = sizeof(Size);
	std::vector<byte> cnt(cntSize, 0);
	memcpy(&cnt[0], &Size, cntSize);
	memcpy(&Buffer[0], &Counter[0], Counter.size());

	for (size_t i = offset; i > 0; i--)
	{
		byte osrc, odst, ndst;
		odst = Buffer[i];
		osrc = offset - i < cnt.size() ? cnt[offset - i] : (byte)0;
		ndst = (byte)(odst + osrc + carry);
		carry = ndst < odst ? 1 : 0;
		Buffer[i] = ndst;
	}
}

bool CTRDrbg::IsValidKeySize(const size_t KeySize)
{
	for (size_t i = 0; i < m_blockCipher->LegalKeySizes().size(); ++i)
	{
		if (KeySize == m_blockCipher->LegalKeySizes()[i])
			break;
		if (i == m_blockCipher->LegalKeySizes().size() - 1)
			return false;
	}
	return true;
}

void CTRDrbg::Scope()
{
	Detect();

	m_processorCount = ParallelUtils::ProcessorCount();

	if (m_parallelMaxDegree == 1)
	{
		m_isParallel = false;
	}
	else
	{
		if (m_processorCount % 2 != 0)
			m_processorCount--;
		if (m_processorCount > 1)
			m_isParallel = true;
	}

	if (m_parallelMaxDegree == 0)
		m_parallelMaxDegree = m_processorCount;

	if (m_isParallel)
	{
		m_parallelMinimumSize = m_parallelMaxDegree * m_blockCipher->BlockSize();

		if (m_hasAVX)
			m_parallelMinimumSize *= 8;
		else if (m_hasSSE)
			m_parallelMinimumSize *= 4;

		// 16 kb minimum
		if (m_parallelBlockSize == 0 || m_parallelBlockSize < PARALLEL_DEFBLOCK / 4)
			m_parallelBlockSize = PARALLEL_DEFBLOCK - (PARALLEL_DEFBLOCK % m_parallelMinimumSize);
		else
			m_parallelBlockSize = m_parallelBlockSize - (m_parallelBlockSize % m_parallelMinimumSize);

		if (m_thdVectors.size() != m_parallelMaxDegree)
			m_thdVectors.resize(m_parallelMaxDegree);
		for (size_t i = 0; i < m_parallelMaxDegree; ++i)
			m_thdVectors[i].resize(m_blockSize);
	}
}

void CTRDrbg::Transform(std::vector<byte> &Output, size_t OutOffset)
{
	size_t outSize = Output.size() - OutOffset;

	if (!m_isParallel || outSize < m_parallelBlockSize)
	{
		// generate random
		Generate(Output, OutOffset, outSize, m_ctrVector);
	}
	else
	{
		// parallel CTR processing //
		const size_t CNKSZE = (outSize / m_blockSize / m_processorCount) * m_blockSize;
		const size_t RNDSZE = CNKSZE * m_processorCount;
		const size_t SUBSZE = (CNKSZE / m_blockSize);
		// create jagged array of 'sub counters'
		m_thdVectors.resize(m_processorCount);

		ParallelUtils::ParallelFor(0, m_processorCount, [this, &Output, CNKSZE, RNDSZE, SUBSZE, OutOffset](size_t i)
		{
			std::vector<byte> &iv = m_thdVectors[i];
			// offset counter by chunk size / block size
			this->Increase(m_ctrVector, SUBSZE * i, iv);
			// create random at offset position
			this->Generate(Output, OutOffset + (i * CNKSZE), CNKSZE, iv);
		});

		// last block processing
		if (RNDSZE < outSize)
		{
			size_t fnlSize = outSize % RNDSZE;
			Generate(Output, OutOffset + RNDSZE, fnlSize, m_thdVectors[m_processorCount - 1]);
		}

		// copy the last counter position to class variable
		memcpy(&m_ctrVector[0], &m_thdVectors[m_processorCount - 1][0], m_ctrVector.size());
	}
}

NAMESPACE_GENERATOREND