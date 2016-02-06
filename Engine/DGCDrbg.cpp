#include "DGCDrbg.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_GENERATOR

void DGCDrbg::Destroy()
{
	if (!_isDestroyed)
	{
		CEX::Utility::IntUtils::ClearVector(_dgtSeed);
		CEX::Utility::IntUtils::ClearVector(_dgtState);

		_isInitialized = true;
		_keySize = 0;
		_stateCtr = 0;
		_seedCtr = 0;
		_isDestroyed = true;
	}
}

unsigned int DGCDrbg::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

unsigned int DGCDrbg::Generate(std::vector<byte> &Output, unsigned int OutOffset, unsigned int Size)
{
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("DGCDrbg:Generate", "Output buffer too small!");

	unsigned int offset = 0;
	unsigned int len = OutOffset + Size;

	GenerateState();

	for (unsigned int i = OutOffset; i < len; ++i)
	{
		if (offset == _dgtState.size())
		{
			GenerateState();
			offset = 0;
		}

		Output[i] = _dgtState[offset++];
	}

	return Size;
}

void DGCDrbg::Initialize(const std::vector<byte> &Salt)
{
	if (Salt.size() < COUNTER_SIZE)
		throw CryptoGeneratorException("DGCDrbg:Initialize", "Salt must be at least 8 bytes!");

	const unsigned int ctrSize = sizeof(long);
	std::vector<long> counter(1);
	unsigned int keyLen = (Salt.size() - ctrSize) < 0 ? 0 : Salt.size() - ctrSize;
	std::vector<byte> key(keyLen);
	memcpy(&counter[0], &Salt[0], ctrSize);

	if (keyLen != 0)
	{
		memcpy(&key[0], &Salt[ctrSize], keyLen);
		UpdateSeed(key);
	}

	UpdateCounter(counter[0]);
	_isInitialized = true;
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
	const unsigned int ctrSize = sizeof(long);

	if (Salt.size() < ctrSize)
		throw CryptoGeneratorException("DGCDrbg:Update", "Minimum key size has not been added. Size must be at least 8 bytes!");

	// update seed and counter
	if (Salt.size() >= _msgDigest->BlockSize() + ctrSize)
	{
		Initialize(Salt);
	}
	else if (Salt.size() == _msgDigest->BlockSize())
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

// *** Protected *** //

void DGCDrbg::CycleSeed()
{
	_msgDigest->BlockUpdate(_dgtSeed, 0, _dgtSeed.size());
	IncrementCounter(_seedCtr++);
	_msgDigest->DoFinal(_dgtSeed, 0);
}

void DGCDrbg::IncrementCounter(long Counter)
{
	for (int i = 0; i < 8; i++)
	{
		_msgDigest->Update((byte)Counter);
		Counter >>= 8;
	}
}

void DGCDrbg::GenerateState()
{
	CEX::Utility::ParallelUtils::lock<std::mutex> lock(_mtxLock);
	IncrementCounter(_stateCtr++);
	_msgDigest->BlockUpdate(_dgtState, 0, _dgtState.size());
	_msgDigest->BlockUpdate(_dgtSeed, 0, _dgtSeed.size());
	_msgDigest->DoFinal(_dgtState, 0);

	if ((_stateCtr % CYCLE_COUNT) == 0)
		CycleSeed();
}

void DGCDrbg::UpdateCounter(long Counter)
{
	CEX::Utility::ParallelUtils::lock<std::mutex> lock(_mtxLock);
	IncrementCounter(Counter);
	_msgDigest->BlockUpdate(_dgtSeed, 0, _dgtSeed.size());
	_msgDigest->DoFinal(_dgtSeed, 0);
}

void DGCDrbg::UpdateSeed(std::vector<byte> Seed)
{
	CEX::Utility::ParallelUtils::lock<std::mutex> lock(_mtxLock);
	_msgDigest->BlockUpdate(Seed, 0, Seed.size());
	_msgDigest->BlockUpdate(_dgtSeed, 0, _dgtSeed.size());
	_msgDigest->DoFinal(_dgtSeed, 0);
}

NAMESPACE_GENERATOREND
