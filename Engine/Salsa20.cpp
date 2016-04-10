#include "Salsa20.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_STREAM

void Salsa20::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_isInitialized = false;
		_processorCount = 0;
		_isParallel = false;
		_parallelBlockSize = 0;
		_rndCount = 0;

		CEX::Utility::IntUtils::ClearVector(_ctrVector);
		CEX::Utility::IntUtils::ClearVector(_wrkState);
		CEX::Utility::IntUtils::ClearVector(_dstCode);
		CEX::Utility::IntUtils::ClearVector(_threadVectors);
	}
}

void Salsa20::Initialize(const CEX::Common::KeyParams &KeyParam)
{
	if (KeyParam.IV().size() != 8)
		throw CryptoSymmetricCipherException("Salsa20:Initialize", "Requires exactly 8 bytes of IV!");
	if (KeyParam.Key().size() != 16 && KeyParam.Key().size() != 32)
		throw CryptoSymmetricCipherException("Salsa20:Initialize", "Key must be 16 or 32 bytes!");

	if (_dstCode.size() == 0)
	{
		std::string info;
		if (KeyParam.Key().size() == 16)
			info = "expand 16-byte k";
		else
			info = "expand 32-byte k";

		_dstCode.reserve(info.size());
		for (size_t i = 0; i < info.size(); ++i)
			_dstCode.push_back(info[i]);
	}

	Reset();
	SetKey(KeyParam.Key(), KeyParam.IV());
	_isInitialized = true;
}

void Salsa20::Reset()
{
	_ctrVector[0] = 0;
	_ctrVector[1] = 0;
}

void Salsa20::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	ProcessBlock(Input, Output);
}

void Salsa20::Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	ProcessBlock(Input, InOffset, Output, OutOffset);
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

void Salsa20::ProcessBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!_isParallel || Output.size() < _parallelBlockSize)
	{
		// generate random
		Generate(Output.size(), _ctrVector, Output, 0);
		// output is input xor with random
		size_t sze = (Output.size() - (Output.size() % BLOCK_SIZE));

		if (sze != 0)
			CEX::Utility::IntUtils::XORBLK(Input, 0, Output, 0, sze);

		// get the remaining bytes
		if (sze != Output.size())
		{
			for (size_t i = sze; i < Output.size(); ++i)
				Output[i] ^= Input[i];
		}
	}
	else
	{
		// parallel CTR processing //
		size_t cnkSize = (Output.size() / BLOCK_SIZE / _processorCount) * BLOCK_SIZE;
		size_t rndSize = cnkSize * _processorCount;
		size_t subSize = (cnkSize / BLOCK_SIZE);
		// create jagged array of 'sub counters'
		_threadVectors.resize(_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, _processorCount, [this, &Input, &Output, cnkSize, rndSize, subSize](size_t i)
		{
			std::vector<uint> &iv = _threadVectors[i];
			// offset counter by chunk size / block size
			this->Increase(_ctrVector, subSize * i, iv);
			// create random at offset position
			this->Generate(cnkSize, iv, Output, (i * cnkSize));
			// xor with input at offset
			CEX::Utility::IntUtils::XORBLK(Input, i * cnkSize, Output, i * cnkSize, cnkSize);
		});

		// last block processing
		if (rndSize < Output.size())
		{
			size_t fnlSize = Output.size() % rndSize;
			Generate(fnlSize, _threadVectors[_processorCount - 1], Output, rndSize);

			for (size_t i = rndSize; i < Output.size(); ++i)
				Output[i] ^= Input[i];
		}

		// copy the last counter position to class variable
		memcpy(&_ctrVector[0], &_threadVectors[_processorCount - 1][0], _ctrVector.size() * sizeof(uint));
	}
}

void Salsa20::ProcessBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset)
{
	size_t outSize = _isParallel ? (Output.size() - OutOffset) : BLOCK_SIZE;

	if (outSize < _parallelBlockSize)
	{
		// generate random
		Generate(outSize, _ctrVector, Output, OutOffset);
		// output is input xor with random
		size_t sze = outSize - (outSize % BLOCK_SIZE);

		if (sze != 0)
			CEX::Utility::IntUtils::XORBLK(Input, InOffset, Output, OutOffset, sze);

		// get the remaining bytes
		if (sze != outSize)
		{
			for (size_t i = sze; i < outSize; ++i)
				Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
	else
	{
		// parallel CTR processing //
		size_t cnkSize = _parallelBlockSize / _processorCount;
		size_t rndSize = cnkSize * _processorCount;
		size_t subSize = cnkSize / BLOCK_SIZE;

		// create jagged array of 'sub counters'
		_threadVectors.resize(_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, _processorCount, [this, &Input, InOffset, &Output, OutOffset, cnkSize, rndSize, subSize](size_t i)
		{
			std::vector<uint> &iv = _threadVectors[i];
			// offset counter by chunk size / block size
			this->Increase(_ctrVector, subSize * i, iv);
			// create random at offset position
			this->Generate(cnkSize, iv, Output, (i * cnkSize));
			// xor with input at offset
			CEX::Utility::IntUtils::XORBLK(Input, InOffset + (i * cnkSize), Output, OutOffset + (i * cnkSize), cnkSize);
		});

		// copy the last counter position to class variable
		memcpy(&_ctrVector[0], &_threadVectors[_processorCount - 1][0], _ctrVector.size() * sizeof(uint));
	}
}

void Salsa20::ProcessBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	size_t outSize = Length;

	if (!_isParallel || outSize < _parallelBlockSize)
	{
		// generate random
		Generate(outSize, _ctrVector, Output, OutOffset);
		// output is input xor with random
		size_t sze = Length - (Length % BLOCK_SIZE);

		if (sze != 0)
			CEX::Utility::IntUtils::XORBLK(Input, InOffset, Output, OutOffset, sze);

		// get the remaining bytes
		if (sze != OutOffset + Length)
		{
			for (size_t i = sze; i < Output.size(); ++i)
				Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
	else
	{
		// parallel CTR processing //
		size_t cnkSize = (Length / BLOCK_SIZE / _processorCount) * BLOCK_SIZE;
		size_t rndSize = cnkSize * _processorCount;
		size_t subSize = (cnkSize / BLOCK_SIZE);

		// create jagged array of 'sub counters'
		_threadVectors.resize(_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, _processorCount, [this, &Input, InOffset, &Output, OutOffset, cnkSize, rndSize, subSize](size_t i)
		{
			std::vector<uint> &Vec = _threadVectors[i];
			// offset counter by chunk size / block size
			this->Increase(_ctrVector, subSize * i, Vec);
			// create random at offset position
			this->Generate(cnkSize, Vec, Output, (i * cnkSize));
			// xor with input at offset
			CEX::Utility::IntUtils::XORBLK(Input, InOffset + (i * cnkSize), Output, OutOffset + (i * cnkSize), cnkSize);
		});

		// last block processing
		if (rndSize < Length)
		{
			size_t fnlSize = Length % rndSize;
			Generate(fnlSize, _threadVectors[_processorCount - 1], Output, rndSize);

			for (size_t i = 0; i < fnlSize; ++i)
				Output[i + OutOffset + rndSize] ^= (byte)(Input[i + InOffset + rndSize]);
		}

		// copy the last counter position to class variable
		size_t x = sizeof(_ctrVector);
		memcpy(&_ctrVector[0], &_threadVectors[_processorCount - 1][0], _ctrVector.size() * sizeof(uint));
	}
}

void Salsa20::SalsaCore(std::vector<byte> &Output, size_t OutOffset, const std::vector<uint> &Counter)
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

void Salsa20::SetScope()
{
	_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (_processorCount % 2 != 0)
		_processorCount--;
	if (_processorCount > 1)
		_isParallel = true;
}

NAMESPACE_STREAMEND