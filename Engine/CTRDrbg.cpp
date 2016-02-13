#include "CTRDrbg.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_GENERATOR

void CTRDrbg::Destroy()
{
	if (!_isDestroyed)
	{
		_blockSize = 0;
		_isEncryption = false;
		_isInitialized = false;
		_processorCount = 0;
		_isParallel = false;
		_keySize = 0;
		_parallelBlockSize = 0;

		CEX::Utility::IntUtils::ClearVector(_ctrVector);
		CEX::Utility::IntUtils::ClearVector(_threadVectors);

		_isDestroyed = true;
	}
}

size_t CTRDrbg::Generate(std::vector<byte> &Output)
{
	Transform(Output, 0);

	return Output.size();
}

size_t CTRDrbg::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("CTRDrbg:Generate", "Output buffer too small!");

	Transform(Output, OutOffset);

	return Size;
}

void CTRDrbg::Initialize(const std::vector<byte> &Salt)
{
	if (Salt.size() != _keySize + _blockSize)
		throw CryptoGeneratorException("CTRDrbg:Initialize", "Salt size is too small; must be key size plus the blocksize!");

	memcpy(&_ctrVector[0], &Salt[0], _blockSize);
	size_t keyLen = Salt.size() - _blockSize;
	std::vector<byte> key(keyLen);
	memcpy(&key[0], &Salt[_blockSize], keyLen);

	_blockCipher->Initialize(true, CEX::Common::KeyParams(key));
	_isInitialized = true;
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

void CTRDrbg::Update(const std::vector<byte> &Salt)
{
	if (Salt.size() == 0)
		throw CryptoGeneratorException("CTRDrbg:Update", "Salt is too small!");

	if (Salt.size() >= _keySize)
		Initialize(Salt);
	else if (Salt.size() >= _blockSize)
		memcpy(&_ctrVector[0], &Salt[0], _ctrVector.size());
}

// *** Protected *** //

void CTRDrbg::Generate(const size_t Length, std::vector<byte> &Counter, std::vector<byte> &Output, const size_t OutOffset)
{
	size_t aln = Length - (Length % _blockSize);
	size_t ctr = 0;

	while (ctr != aln)
	{
		_blockCipher->EncryptBlock(Counter, 0, Output, OutOffset + ctr);
		Increment(Counter);
		ctr += _blockSize;
	}

	if (ctr != Length)
	{
		std::vector<byte> outputBlock(_blockSize, 0);
		_blockCipher->EncryptBlock(Counter, outputBlock);
		size_t fnlSize = Length % _blockSize;
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
	for (size_t i = 0; i < _blockCipher->LegalKeySizes().size(); ++i)
	{
		if (KeySize == _blockCipher->LegalKeySizes()[i])
			break;
		if (i == _blockCipher->LegalKeySizes().size() - 1)
			return false;
	}
	return true;
}

void CTRDrbg::SetScope()
{
	_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();

	if (_processorCount % 2 != 0)
		_processorCount--;
	if (_processorCount > 1)
		_isParallel = true;
}

void CTRDrbg::Transform(std::vector<byte> &Output, size_t OutOffset)
{
	size_t outSize = Output.size() - OutOffset;

	if (!_isParallel || outSize < _parallelBlockSize)
	{
		// generate random
		Generate(outSize, _ctrVector, Output, OutOffset);
	}
	else
	{
		// parallel CTR processing //
		size_t cnkSize = (outSize / _blockSize / _processorCount) * _blockSize;
		size_t rndSize = cnkSize * _processorCount;
		size_t subSize = (cnkSize / _blockSize);
		// create jagged array of 'sub counters'
		_threadVectors.resize(_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, _processorCount, [this, &Output, cnkSize, rndSize, subSize, OutOffset](size_t i)
		{
			std::vector<byte> &iv = _threadVectors[i];
			// offset counter by chunk size / block size
			this->Increase(_ctrVector, subSize * i, iv);
			// create random at offset position
			this->Generate(cnkSize, iv, Output, OutOffset + (i * cnkSize));
		});

		// last block processing
		if (rndSize < outSize)
		{
			size_t fnlSize = outSize % rndSize;
			Generate(fnlSize, _threadVectors[_processorCount - 1], Output, OutOffset + rndSize);
		}

		// copy the last counter position to class variable
		memcpy(&_ctrVector[0], &_threadVectors[_processorCount - 1][0], _ctrVector.size());
	}
}

NAMESPACE_GENERATOREND