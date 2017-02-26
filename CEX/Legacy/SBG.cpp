#include "SBG.h"
#include "Salsa.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"
#include "ProviderFromName.h"

NAMESPACE_DRBG

using Utility::IntUtils;
using Cipher::Symmetric::Stream::Salsa;

//~~~Public Methods~~~//

void SBG::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_hasAVX2 = false;
		m_hasSSE = false;
		m_isInitialized = false;
		m_isParallel = false;
		m_parallelBlockSize = 0;
		m_parallelMaxDegree = 0;
		m_parallelMinimumSize = 0;
		m_processorCount = 0;
		m_rndCount = 0;
		try
		{
			IntUtils::ClearVector(m_ctrVector);
			IntUtils::ClearVector(m_dstCode);
			IntUtils::ClearVector(m_legalSeedSizes);
			IntUtils::ClearVector(m_legalRounds);
			IntUtils::ClearVector(m_wrkState);//
		}
		catch (std::exception& ex)
		{
			throw CryptoGeneratorException("SBG::Destroy", "Could not clear all variables!", std::string(ex.what()));
		}
	}
}

size_t SBG::Generate(std::vector<byte> &Output)
{
	if (Output.size() == 0)
		throw CryptoGeneratorException("SBG:Initialize", "The output array size can not be zero length!");

	Process(Output, 0, Output.size());
	return Output.size();
}

size_t SBG::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!m_isInitialized)
		throw CryptoGeneratorException("SBG:Generate", "The generator must be initialized before generate can be called!");
	if (Output.size() - Length < OutOffset)
		throw CryptoGeneratorException("SBG:Generate", "Output buffer too small!");

	Process(Output, OutOffset, Length);
	return Length;
}

void SBG::Initialize(const RngParams &GenParam)
{
	if (GenParam.Nonce().size() != 0)
	{
		if (GenParam.Info().size() != 0)
			Initialize(GenParam.Seed(), GenParam.Nonce(), GenParam.Info());
		else
			Initialize(GenParam.Seed(), GenParam.Nonce());
	}
	else
	{
		Initialize(GenParam.Seed());
	}
}

void SBG::Initialize(const std::vector<byte> &Seed)
{
	// recheck params
	Scope();

	if (Seed.size() != m_legalSeedSizes[0] && Seed.size() != m_legalSeedSizes[1])
		throw CryptoGeneratorException("SBG:Initialize", "Seed material size is too small; must be exactly 24 (128 bit key) or 40 bytes (256 bit key)!");
	if (IsParallel() && ParallelBlockSize() < ParallelMinimumSize() || ParallelBlockSize() > ParallelMaximumSize())
		throw CryptoGeneratorException("SBG:Initialize", "The parallel block size is out of bounds!");
	if (IsParallel() && ParallelBlockSize() % ParallelMinimumSize() != 0)
		throw CryptoGeneratorException("SBG:Initialize", "The parallel block size must be evenly aligned to the ParallelMinimumSize!");

	std::string info;
	if (Seed.size() == 24)
		info = "expand 16-byte k";
	else
		info = "expand 32-byte k";

	m_dstCode.reserve(info.size());
	for (size_t i = 0; i < info.size(); ++i)
		m_dstCode.push_back(info[i]);

	std::vector<byte> iv(CTR_SIZE);
	memcpy(&iv[0], &Seed[0], CTR_SIZE);
	size_t keyLen = Seed.size() - CTR_SIZE;
	std::vector<byte> tmpKey(keyLen);
	memcpy(&tmpKey[0], &Seed[CTR_SIZE], keyLen);
	Expand(tmpKey, iv);
	m_isInitialized = true;
}

void SBG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce)
{
	std::vector<byte> tmpKey(Nonce.size() + Seed.size());
	memcpy(&tmpKey[0], &Seed[0], Seed.size());
	memcpy(&tmpKey[Seed.size()], &Nonce[0], Nonce.size());
	Initialize(tmpKey);
}

void SBG::Initialize(const std::vector<byte> &Nonce, const std::vector<byte> &Seed, const std::vector<byte> &Info)
{
	std::vector<byte> tmpKey(Nonce.size() + Seed.size() + Info.size());
	memcpy(&tmpKey[0], &Seed[0], Seed.size());
	memcpy(&tmpKey[Seed.size()], &Nonce[0], Nonce.size());
	memcpy(&tmpKey[Seed.size() + Nonce.size()], &Info[0], Info.size());
	Initialize(tmpKey);
}

void SBG::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0)
		throw CryptoGeneratorException("SBG::ParallelMaxDegree", "Parallel degree can not be zero!");
	if (Degree % 2 != 0)
		throw CryptoGeneratorException("SBG::ParallelMaxDegree", "Parallel degree must be an even number!");
	if (Degree > m_processorCount)
		throw CryptoGeneratorException("SBG::ParallelMaxDegree", "Parallel degree can not exceed processor count!");

	m_parallelMaxDegree = Degree;
	Scope();
}

void SBG::Update(const std::vector<byte> &Seed)
{
	if (Seed.size() < CTR_SIZE || Seed.size() != m_legalSeedSizes[0] && Seed.size() != m_legalSeedSizes[1])
		throw CryptoGeneratorException("SBG:Update", "Seed is too small!");

	if (Seed.size() == m_legalSeedSizes[0] || Seed.size() == m_legalSeedSizes[1])
		Initialize(Seed);
	else if (Seed.size() == CTR_SIZE)
		memcpy(&m_ctrVector[0], &Seed[0], m_ctrVector.size());
}

//~~~Private Methods~~~//

void SBG::Detect()
{
	try
	{
		Common::CpuDetect detect;
		m_processorCount = detect.VirtualCores();

		if (m_processorCount == 0)
			throw std::exception();
		if (m_processorCount > 1 && m_processorCount % 2 != 0)
			m_processorCount--;

		m_hasSSE = detect.SSE();
		m_hasAVX2 = detect.AVX2();
		m_parallelBlockSize = detect.L1DataCacheTotal();

	}
	catch (...)
	{
		m_processorCount = Utility::ParallelUtils::ProcessorCount();

		if (m_processorCount == 0)
			m_processorCount = 1;
		if (m_processorCount > 1 && m_processorCount % 2 != 0)
			m_processorCount--;

		m_hasSSE = false;
		m_hasAVX2 = false;
		m_parallelBlockSize = m_processorCount * PRC_DATACACHE;
	}
}

void SBG::Expand(const std::vector<byte> &Key, const std::vector<byte> &Iv)
{
	if (Key.size() == 32)
	{
		m_wrkState[0] = IntUtils::BytesToLe32(m_dstCode, 0);
		m_wrkState[1] = IntUtils::BytesToLe32(Key, 0);
		m_wrkState[2] = IntUtils::BytesToLe32(Key, 4);
		m_wrkState[3] = IntUtils::BytesToLe32(Key, 8);
		m_wrkState[4] = IntUtils::BytesToLe32(Key, 12);
		m_wrkState[5] = IntUtils::BytesToLe32(m_dstCode, 4);
		m_wrkState[6] = IntUtils::BytesToLe32(Iv, 0);
		m_wrkState[7] = IntUtils::BytesToLe32(Iv, 4);
		m_wrkState[8] = IntUtils::BytesToLe32(m_dstCode, 8);
		m_wrkState[9] = IntUtils::BytesToLe32(Key, 16);
		m_wrkState[10] = IntUtils::BytesToLe32(Key, 20);
		m_wrkState[11] = IntUtils::BytesToLe32(Key, 24);
		m_wrkState[12] = IntUtils::BytesToLe32(Key, 28);
		m_wrkState[13] = IntUtils::BytesToLe32(m_dstCode, 12);
	}
	else
	{
		m_wrkState[0] = IntUtils::BytesToLe32(m_dstCode, 0);
		m_wrkState[1] = IntUtils::BytesToLe32(Key, 0);
		m_wrkState[2] = IntUtils::BytesToLe32(Key, 4);
		m_wrkState[3] = IntUtils::BytesToLe32(Key, 8);
		m_wrkState[4] = IntUtils::BytesToLe32(Key, 12);
		m_wrkState[5] = IntUtils::BytesToLe32(m_dstCode, 4);
		m_wrkState[6] = IntUtils::BytesToLe32(Iv, 0);
		m_wrkState[7] = IntUtils::BytesToLe32(Iv, 4);
		m_wrkState[8] = IntUtils::BytesToLe32(m_dstCode, 8);
		m_wrkState[9] = IntUtils::BytesToLe32(Key, 0);
		m_wrkState[10] = IntUtils::BytesToLe32(Key, 4);
		m_wrkState[11] = IntUtils::BytesToLe32(Key, 8);
		m_wrkState[12] = IntUtils::BytesToLe32(Key, 12);
		m_wrkState[13] = IntUtils::BytesToLe32(m_dstCode, 12);
	}
}

void SBG::Generate(std::vector<byte> &Output, const size_t OutOffset, std::vector<uint> &Counter, const size_t Length)
{
	size_t ctr = 0;
	const size_t SSEBLK = 4 * BLOCK_SIZE;
	const size_t AVXBLK = 8 * BLOCK_SIZE;

	if (m_hasAVX2 && Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		std::vector<uint> ctrBlk(16);

		// process 8 blocks (uses avx if available)
		while (ctr != PBKALN)
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
			Salsa::Transform512(Output, OutOffset + ctr, ctrBlk, m_wrkState, m_rndCount);
			ctr += AVXBLK;
		}
	}
	else if (m_hasSSE && Length >= SSEBLK)
	{
		const size_t PBKALN = Length - (Length % SSEBLK);
		std::vector<uint> ctrBlk(8);

		// process 4 blocks (uses sse intrinsics if available)
		while (ctr != PBKALN)
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
			Salsa::Transform256(Output, OutOffset + ctr, ctrBlk, m_wrkState, m_rndCount);
			ctr += SSEBLK;
		}
	}

	const size_t ALNSZE = Length - (Length % BLOCK_SIZE);
	while (ctr != ALNSZE)
	{
		Salsa::Transform64(Output, OutOffset + ctr, Counter, m_wrkState, m_rndCount);
		Increment(Counter);
		ctr += BLOCK_SIZE;
	}

	if (ctr != Length)
	{
		std::vector<byte> outputBlock(BLOCK_SIZE, 0);
		Salsa::Transform64(outputBlock, 0, Counter, m_wrkState, m_rndCount);
		const size_t FNLSZE = Length % BLOCK_SIZE;
		memcpy(&Output[OutOffset + (Length - FNLSZE)], &outputBlock[0], FNLSZE);
		Increment(Counter);
	}
}

void SBG::Increase(const std::vector<uint> &Input, std::vector<uint> &Output, const size_t Length)
{
	Output = Input;

	for (size_t i = 0; i < Length; i++)
		Increment(Output);
}

void SBG::Increment(std::vector<uint> &Counter)
{
	if (++Counter[0] == 0)
		++Counter[1];
}

IProvider* SBG::LoadProvider(Providers ProviderType)
{
	try
	{
		return Helper::ProviderFromName::GetInstance(ProviderType);
	}
	catch (std::exception& ex)
	{
		throw CryptoGeneratorException("SBG:LoadProvider", "The entropy provider could not be instantiated!", std::string(ex.what()));
	}
}

void SBG::Process(std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	const size_t PRCSZE = Length >= Output.size() - OutOffset ? Length : Output.size() - OutOffset;

	if (!m_isParallel || PRCSZE < m_parallelMinimumSize)
	{
		// generate random
		Generate(Output, OutOffset, m_ctrVector, PRCSZE);
	}
	else
	{
		// parallel CTR processing //
		const size_t CNKSZE = (PRCSZE / BLOCK_SIZE / m_parallelMaxDegree) * BLOCK_SIZE;
		const size_t RNDSZE = CNKSZE * m_parallelMaxDegree;
		const size_t CTRLEN = (CNKSZE / BLOCK_SIZE);
		std::vector<uint> tmpCtr(m_ctrVector.size());

		Utility::ParallelUtils::ParallelFor(0, m_parallelMaxDegree, [this, &Output, OutOffset, &tmpCtr, CNKSZE, CTRLEN](size_t i)
		{
			// thread level counter
			std::vector<uint> thdCtr(m_ctrVector.size());
			// offset counter by chunk size / block size
			this->Increase(m_ctrVector, thdCtr, CTRLEN * i);
			// create random at offset position
			this->Generate(Output, (i * CNKSZE), thdCtr, CNKSZE);
			// store last counter
			if (i == m_parallelMaxDegree - 1)
				memcpy(&tmpCtr[0], &thdCtr[0], CTR_SIZE);
		});

		// last block processing
		if (RNDSZE < PRCSZE)
		{
			const size_t FNLSZE = PRCSZE % RNDSZE;
			Generate(Output, RNDSZE, tmpCtr, FNLSZE);
		}

		// copy the last counter position to class variable
		memcpy(&m_ctrVector[0], &tmpCtr[0], CTR_SIZE);
	}
}

void SBG::Scope()
{
	Detect();

	m_processorCount = Utility::ParallelUtils::ProcessorCount();
	if (m_processorCount % 2 != 0)
		m_processorCount--;

	if (m_parallelMaxDegree == 1)
		m_isParallel = false;
	else if (!m_isInitialized)
		m_isParallel = (m_processorCount > 1);

	if (m_parallelMaxDegree == 0)
		m_parallelMaxDegree = m_processorCount;

	m_parallelMinimumSize = m_parallelMaxDegree * BLOCK_SIZE;

	if (m_hasAVX2)
		m_parallelMinimumSize *= 8;
	else if (m_hasSSE)
		m_parallelMinimumSize *= 4;

	// 16 kb minimum
	if (m_parallelBlockSize == 0 || m_parallelBlockSize < PRC_DATACACHE / 2)
		m_parallelBlockSize = (m_processorCount * PRC_DATACACHE) - ((m_processorCount * PRC_DATACACHE) % m_parallelMinimumSize);
	else
		m_parallelBlockSize = m_parallelBlockSize - (m_parallelBlockSize % m_parallelMinimumSize);
}

NAMESPACE_DRBGEND