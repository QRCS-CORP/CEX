#include "SP20Drbg.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_GENERATOR

void SP20Drbg::Destroy()
{
	if (!_isDestroyed)
	{
		_isInitialized = false;
		_processorCount = 0;
		_isParallel = false;
		_parallelBlockSize = 0;
		_rndCount = 0;

		CEX::Utility::IntUtils::ClearVector(_ctrVector);
		CEX::Utility::IntUtils::ClearVector(_dstCode);
		CEX::Utility::IntUtils::ClearVector(_legalRounds);
		CEX::Utility::IntUtils::ClearVector(_threadVectors);
		CEX::Utility::IntUtils::ClearVector(_wrkState);

		_isDestroyed = true;
	}
}

size_t SP20Drbg::Generate(std::vector<byte> &Output)
{
	Transform(Output, 0);
	return Output.size();
}

size_t SP20Drbg::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("SP20Drbg:Generate", "Output buffer too small!");

	Transform(Output, OutOffset);
	return Size;
}

void SP20Drbg::Initialize(const std::vector<byte> &Salt)
{
	if (Salt.size() != _legalKeySizes[0] + VECTOR_SIZE && Salt.size() != _legalKeySizes[1] + VECTOR_SIZE)
		throw CryptoGeneratorException("SP20Drbg:Initialize", "Key material size is too small; must be exactly 24 (128 bit key) or 40 bytes (256 bit key)!");

	std::string info;
	if (Salt.size() == 24)
		info = "expand 16-byte k";
	else
		info = "expand 32-byte k";

	_dstCode.reserve(info.size());
	for (size_t i = 0; i < info.size(); ++i)
		_dstCode.push_back(info[i]);

	std::vector<byte> iv(VECTOR_SIZE);
	memcpy(&iv[0], &Salt[0], VECTOR_SIZE);
	size_t keyLen = Salt.size() - VECTOR_SIZE;
	std::vector<byte> key(keyLen);
	memcpy(&key[0], &Salt[VECTOR_SIZE], keyLen);
	SetKey(key, iv);
	_isInitialized = true;
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
	if (Salt.size() == 0)
		throw CryptoGeneratorException("SP20Drbg:Update", "Salt is too small!");

	if (Salt.size() == _legalKeySizes[0] + VECTOR_SIZE || Salt.size() == _legalKeySizes[1] + VECTOR_SIZE)
		Initialize(Salt);
	else if (Salt.size() == VECTOR_SIZE)
		memcpy(&_ctrVector[0], &Salt[0], _ctrVector.size());
	else
		throw CryptoGeneratorException("SP20Drbg:Update", "Salt must be either 40 bytes; (key and vector), or 8 bytes; (vector only) in length!");
}

// *** Protected *** //

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
	uint X0 = _wrkState[ctr];
	uint X1 = _wrkState[++ctr];
	uint X2 = _wrkState[++ctr];
	uint X3 = _wrkState[++ctr];
	uint X4 = _wrkState[++ctr];
	uint X5 = _wrkState[++ctr];
	uint X6 = _wrkState[++ctr];
	uint X7 = _wrkState[++ctr];
	uint X8 = Counter[0];
	uint X9 = Counter[1];
	uint X10 = _wrkState[++ctr];
	uint X11 = _wrkState[++ctr];
	uint X12 = _wrkState[++ctr];
	uint X13 = _wrkState[++ctr];
	uint X14 = _wrkState[++ctr];
	uint X15 = _wrkState[++ctr];

	ctr = _rndCount;
	while (ctr != 0)
	{
		X4 ^= CEX::Utility::IntUtils::RotateLeft(X0 + X12, 7);
		X8 ^= CEX::Utility::IntUtils::RotateLeft(X4 + X0, 9);
		X12 ^= CEX::Utility::IntUtils::RotateLeft(X8 + X4, 13);
		X0 ^= CEX::Utility::IntUtils::RotateLeft(X12 + X8, 18);
		X9 ^= CEX::Utility::IntUtils::RotateLeft(X5 + X1, 7);
		X13 ^= CEX::Utility::IntUtils::RotateLeft(X9 + X5, 9);
		X1 ^= CEX::Utility::IntUtils::RotateLeft(X13 + X9, 13);
		X5 ^= CEX::Utility::IntUtils::RotateLeft(X1 + X13, 18);
		X14 ^= CEX::Utility::IntUtils::RotateLeft(X10 + X6, 7);
		X2 ^= CEX::Utility::IntUtils::RotateLeft(X14 + X10, 9);
		X6 ^= CEX::Utility::IntUtils::RotateLeft(X2 + X14, 13);
		X10 ^= CEX::Utility::IntUtils::RotateLeft(X6 + X2, 18);
		X3 ^= CEX::Utility::IntUtils::RotateLeft(X15 + X11, 7);
		X7 ^= CEX::Utility::IntUtils::RotateLeft(X3 + X15, 9);
		X11 ^= CEX::Utility::IntUtils::RotateLeft(X7 + X3, 13);
		X15 ^= CEX::Utility::IntUtils::RotateLeft(X11 + X7, 18);
		X1 ^= CEX::Utility::IntUtils::RotateLeft(X0 + X3, 7);
		X2 ^= CEX::Utility::IntUtils::RotateLeft(X1 + X0, 9);
		X3 ^= CEX::Utility::IntUtils::RotateLeft(X2 + X1, 13);
		X0 ^= CEX::Utility::IntUtils::RotateLeft(X3 + X2, 18);
		X6 ^= CEX::Utility::IntUtils::RotateLeft(X5 + X4, 7);
		X7 ^= CEX::Utility::IntUtils::RotateLeft(X6 + X5, 9);
		X4 ^= CEX::Utility::IntUtils::RotateLeft(X7 + X6, 13);
		X5 ^= CEX::Utility::IntUtils::RotateLeft(X4 + X7, 18);
		X11 ^= CEX::Utility::IntUtils::RotateLeft(X10 + X9, 7);
		X8 ^= CEX::Utility::IntUtils::RotateLeft(X11 + X10, 9);
		X9 ^= CEX::Utility::IntUtils::RotateLeft(X8 + X11, 13);
		X10 ^= CEX::Utility::IntUtils::RotateLeft(X9 + X8, 18);
		X12 ^= CEX::Utility::IntUtils::RotateLeft(X15 + X14, 7);
		X13 ^= CEX::Utility::IntUtils::RotateLeft(X12 + X15, 9);
		X14 ^= CEX::Utility::IntUtils::RotateLeft(X13 + X12, 13);
		X15 ^= CEX::Utility::IntUtils::RotateLeft(X14 + X13, 18);
		ctr -= 2;
	}

	CEX::Utility::IntUtils::Le32ToBytes(X0 + _wrkState[ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X1 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X2 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X3 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X4 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X5 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X6 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X7 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X8 + Counter[0], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X9 + Counter[1], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X10 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X11 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X12 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X13 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X14 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	CEX::Utility::IntUtils::Le32ToBytes(X15 + _wrkState[++ctr], Output, OutOffset);
}

void SP20Drbg::SetKey(const std::vector<byte> &Key, const std::vector<byte> &Iv)
{
	if (Key.size() == 32)
	{
		_wrkState[0] = CEX::Utility::IntUtils::BytesToLe32(_dstCode, 0);
		_wrkState[1] = CEX::Utility::IntUtils::BytesToLe32(Key, 0);
		_wrkState[2] = CEX::Utility::IntUtils::BytesToLe32(Key, 4);
		_wrkState[3] = CEX::Utility::IntUtils::BytesToLe32(Key, 8);
		_wrkState[4] = CEX::Utility::IntUtils::BytesToLe32(Key, 12);
		_wrkState[5] = CEX::Utility::IntUtils::BytesToLe32(_dstCode, 4);
		_wrkState[6] = CEX::Utility::IntUtils::BytesToLe32(Iv, 0);
		_wrkState[7] = CEX::Utility::IntUtils::BytesToLe32(Iv, 4);
		_wrkState[8] = CEX::Utility::IntUtils::BytesToLe32(_dstCode, 8);
		_wrkState[9] = CEX::Utility::IntUtils::BytesToLe32(Key, 16);
		_wrkState[10] = CEX::Utility::IntUtils::BytesToLe32(Key, 20);
		_wrkState[11] = CEX::Utility::IntUtils::BytesToLe32(Key, 24);
		_wrkState[12] = CEX::Utility::IntUtils::BytesToLe32(Key, 28);
		_wrkState[13] = CEX::Utility::IntUtils::BytesToLe32(_dstCode, 12);
	}
	else
	{
		_wrkState[0] = CEX::Utility::IntUtils::BytesToLe32(_dstCode, 0);
		_wrkState[1] = CEX::Utility::IntUtils::BytesToLe32(Key, 0);
		_wrkState[2] = CEX::Utility::IntUtils::BytesToLe32(Key, 4);
		_wrkState[3] = CEX::Utility::IntUtils::BytesToLe32(Key, 8);
		_wrkState[4] = CEX::Utility::IntUtils::BytesToLe32(Key, 12);
		_wrkState[5] = CEX::Utility::IntUtils::BytesToLe32(_dstCode, 4);
		_wrkState[6] = CEX::Utility::IntUtils::BytesToLe32(Iv, 0);
		_wrkState[7] = CEX::Utility::IntUtils::BytesToLe32(Iv, 4);
		_wrkState[8] = CEX::Utility::IntUtils::BytesToLe32(_dstCode, 8);
		_wrkState[9] = CEX::Utility::IntUtils::BytesToLe32(Key, 0);
		_wrkState[10] = CEX::Utility::IntUtils::BytesToLe32(Key, 4);
		_wrkState[11] = CEX::Utility::IntUtils::BytesToLe32(Key, 8);
		_wrkState[12] = CEX::Utility::IntUtils::BytesToLe32(Key, 12);
		_wrkState[13] = CEX::Utility::IntUtils::BytesToLe32(_dstCode, 12);
	}
}

void SP20Drbg::SetScope()
{
	_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (_processorCount % 2 != 0)
		_processorCount--;
	if (_processorCount > 1)
		_isParallel = true;
}

void SP20Drbg::Transform(std::vector<byte> &Output, size_t OutOffset)
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
		size_t cnkSize = (outSize / BLOCK_SIZE / _processorCount) * BLOCK_SIZE;
		size_t rndSize = cnkSize * _processorCount;
		size_t subSize = (cnkSize / BLOCK_SIZE);
		// create jagged array of 'sub counters'
		_threadVectors.resize(_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, _processorCount, [this, &Output, cnkSize, rndSize, subSize, OutOffset](size_t i)
		{
			std::vector<uint> &iv = _threadVectors[i];
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