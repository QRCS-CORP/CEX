#include "DGCDrbg.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_GENERATOR

void DGCDrbg::Destroy()
{
	if (!m_isDestroyed)
	{
		CEX::Utility::IntUtils::ClearVector(m_dgtSeed);
		CEX::Utility::IntUtils::ClearVector(m_dgtState);

		m_isInitialized = true;
		m_keySize = 0;
		m_stateCtr = 0;
		m_seedCtr = 0;
		m_isDestroyed = true;
	}
}

size_t DGCDrbg::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

size_t DGCDrbg::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("DGCDrbg:Generate", "Output buffer too small!");
#endif

	size_t offset = 0;
	size_t len = OutOffset + Size;

	GenerateState();

	for (size_t i = OutOffset; i < len; ++i)
	{
		if (offset == m_dgtState.size())
		{
			GenerateState();
			offset = 0;
		}

		Output[i] = m_dgtState[offset++];
	}

	return Size;
}

void DGCDrbg::Initialize(const std::vector<byte> &Ikm)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Ikm.size() < COUNTER_SIZE)
		throw CryptoGeneratorException("DGCDrbg:Initialize", "Salt must be at least 8 bytes!");
#endif

	const size_t ctrSize = sizeof(long);
	std::vector<long> counter(1);
	size_t keyLen = (Ikm.size() - ctrSize) < 0 ? 0 : Ikm.size() - ctrSize;
	std::vector<byte> key(keyLen);
	memcpy(&counter[0], &Ikm[0], ctrSize);

	if (keyLen != 0)
	{
		memcpy(&key[0], &Ikm[ctrSize], keyLen);
		UpdateSeed(key);
	}

	UpdateCounter(counter[0]);
	m_isInitialized = true;
}

void DGCDrbg::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm)
{
	std::vector<byte> key(Salt.size() + Ikm.size());

	if (Salt.size() > 0)
		memcpy(&key[0], &Salt[0], Salt.size());
	if (Ikm.size() > 0)
		memcpy(&key[Salt.size()], &Ikm[0], Ikm.size());

	Initialize(key);
}

void DGCDrbg::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Nonce)
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

void DGCDrbg::Update(const std::vector<byte> &Salt)
{
	const size_t ctrSize = sizeof(long);
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Salt.size() < ctrSize)
		throw CryptoGeneratorException("DGCDrbg:Update", "Minimum key size has not been added. Size must be at least 8 bytes!");
#endif
	// update seed and counter
	if (Salt.size() >= m_msgDigest->BlockSize() + ctrSize)
	{
		Initialize(Salt);
	}
	else if (Salt.size() == m_msgDigest->BlockSize())
	{
		UpdateSeed(Salt);
	}
	else if (Salt.size() == ctrSize)
	{
		// update counter only
		std::vector<long> counter(1);
		memcpy(&counter[0], &Salt[0], ctrSize);
		UpdateCounter(counter[0]);
	}
	else
	{
		UpdateSeed(Salt);
	}
}

// *** Private *** //

void DGCDrbg::CycleSeed()
{
	m_msgDigest->BlockUpdate(m_dgtSeed, 0, m_dgtSeed.size());
	IncrementCounter(m_seedCtr++);
	m_msgDigest->DoFinal(m_dgtSeed, 0);
}

void DGCDrbg::IncrementCounter(long Counter)
{
	for (int i = 0; i < 8; i++)
	{
		m_msgDigest->Update((byte)Counter);
		Counter >>= 8;
	}
}

void DGCDrbg::GenerateState()
{
	CEX::Utility::ParallelUtils::lock<std::mutex> lock(m_mtxLock);
	IncrementCounter(m_stateCtr++);
	m_msgDigest->BlockUpdate(m_dgtState, 0, m_dgtState.size());
	m_msgDigest->BlockUpdate(m_dgtSeed, 0, m_dgtSeed.size());
	m_msgDigest->DoFinal(m_dgtState, 0);

	if ((m_stateCtr % CYCLE_COUNT) == 0)
		CycleSeed();
}

void DGCDrbg::UpdateCounter(long Counter)
{
	CEX::Utility::ParallelUtils::lock<std::mutex> lock(m_mtxLock);
	IncrementCounter(Counter);
	m_msgDigest->BlockUpdate(m_dgtSeed, 0, m_dgtSeed.size());
	m_msgDigest->DoFinal(m_dgtSeed, 0);
}

void DGCDrbg::UpdateSeed(std::vector<byte> Seed)
{
	CEX::Utility::ParallelUtils::lock<std::mutex> lock(m_mtxLock);
	m_msgDigest->BlockUpdate(Seed, 0, Seed.size());
	m_msgDigest->BlockUpdate(m_dgtSeed, 0, m_dgtSeed.size());
	m_msgDigest->DoFinal(m_dgtSeed, 0);
}

NAMESPACE_GENERATOREND
