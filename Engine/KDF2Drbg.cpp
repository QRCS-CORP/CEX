#include "KDF2Drbg.h"
#include "IntUtils.h"

NAMESPACE_GENERATOR

void KDF2Drbg::Destroy()
{
	if (!_isDestroyed)
	{
		_blockSize = 0;
		_hashSize = 0;
		_isInitialized = false;
		CEX::Utility::IntUtils::ClearVector(_IV);
		CEX::Utility::IntUtils::ClearVector(_Salt);
	}
}

size_t KDF2Drbg::Generate(std::vector<byte> &Output)
{
	GenerateKey(Output, 0, Output.size());
	return Output.size();
}

size_t KDF2Drbg::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("KDF2Drbg:Generate", "Output buffer too small!");

	GenerateKey(Output, OutOffset, Size);
	return Size;
}

void KDF2Drbg::Initialize(const std::vector<byte> &Ikm)
{
	if (Ikm.size() < _hashSize)
		throw CryptoGeneratorException("KDF2Drbg:Initialize", "Salt size is too small; must be a minumum of digest return size!");

	if (Ikm.size() < _blockSize + _hashSize)
	{
		_Salt.resize(Ikm.size());
		_IV.resize(0);
		// interpret as ISO18033, no IV
		memcpy(&_Salt[0], &Ikm[0], Ikm.size());
	}
	else
	{
		_Salt.resize(Ikm.size() - _hashSize);
		_IV.resize(_blockSize);
		memcpy(&_Salt[0], &Ikm[0], Ikm.size() - _hashSize);
		memcpy(&_IV[0], &Ikm[_Salt.size()], _blockSize);
	}

	_isInitialized = true;
}

void KDF2Drbg::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm)
{
	if (Salt.size() < _hashSize)
		throw CryptoGeneratorException("KDF2Drbg:Initialize", "Salt size is too small; must be a minumum of digest return size!");
	if (Ikm.size() < _blockSize)
		throw CryptoGeneratorException("KDF2Drbg:Initialize", "IKM size is too small; must be a minumum of digest block size!");

	// clone iv and salt
	_IV.resize(_blockSize);
	_Salt.resize(Salt.size());

	if (_IV.size() > 0)
		memcpy(&_IV[0], &Ikm[0], _blockSize);
	if (_Salt.size() > 0)
		memcpy(&_Salt[0], &Salt[0], Salt.size());

	_isInitialized = true;
}

void KDF2Drbg::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Nonce)
{
	if (Salt.size() + Nonce.size() < _hashSize)
		throw CryptoGeneratorException("KDF2Drbg:Initialize", "Salt size is too small; must be a minumum of digest return size!");
	if (Ikm.size() < _blockSize)
		throw CryptoGeneratorException("KDF2Drbg:Initialize", "IKM with Nonce size is too small; combined must be a minumum of digest block size!");

	// clone iv and salt
	_IV.resize(_blockSize);
	_Salt.resize(Salt.size() + Nonce.size());

	if (_IV.size() > 0)
		memcpy(&_IV[0], &Ikm[0], _blockSize);
	if (_Salt.size() > 0)
		memcpy(&_Salt[0], &Salt[0], Salt.size());
	if (Nonce.size() > 0)
		memcpy(&_Salt[Salt.size()], &Nonce[0], Nonce.size());

	_isInitialized = true;
}

void KDF2Drbg::Update(const std::vector<byte> &Salt)
{
	if (Salt.size() == 0)
		throw CryptoGeneratorException("KDF2Drbg:Update", "Salt is too small!");

	Initialize(Salt);
}

// *** Protected *** //

size_t KDF2Drbg::GenerateKey(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
	size_t maxCtr = (size_t)((Size + _hashSize - 1) / _hashSize);
	// only difference between v1 & v2; starts at 0 or 1
	uint counter = 1;
	std::vector<byte> hash(_hashSize);

	for (size_t i = 0; i < maxCtr; i++)
	{
		_msgDigest->BlockUpdate(_Salt, 0, _Salt.size());
		_msgDigest->Update((byte)(counter >> 24));
		_msgDigest->Update((byte)(counter >> 16));
		_msgDigest->Update((byte)(counter >> 8));
		_msgDigest->Update((byte)counter);

		if (_IV.size() != 0)
			_msgDigest->BlockUpdate(_IV, 0, _IV.size());

		_msgDigest->DoFinal(hash, 0);

		if (Size > _hashSize)
		{
			memcpy(&Output[OutOffset], &hash[0], _hashSize);
			OutOffset += _hashSize;
			Size -= _hashSize;
		}
		else
		{
			memcpy(&Output[OutOffset], &hash[0], Size);
		}

		counter++;
	}

	_msgDigest->Reset();

	return Size;
}

NAMESPACE_GENERATOREND
