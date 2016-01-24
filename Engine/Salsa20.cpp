#include "Salsa20.h"
#include "IntUtils.h"

NAMESPACE_STREAM

using CEX::Utility::IntUtils;

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

		IntUtils::ClearVector(_ctrVector);
		IntUtils::ClearVector(_wrkState);
		IntUtils::ClearVector(_dstCode);
		IntUtils::ClearVector(_threadVectors);
	}
}

void Salsa20::Initialize(const KeyParams &KeyParam)
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
		for (unsigned int i = 0; i < info.size(); ++i)
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

void Salsa20::Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	ProcessBlock(Input, InOffset, Output, OutOffset);
}

void Salsa20::Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset, const unsigned int Length)
{
	ProcessBlock(Input, InOffset, Output, OutOffset, Length);
}

// ** Key Schedule ** //

void Salsa20::SetKey(const std::vector<byte> &Key, const std::vector<byte> &Iv)
{
	if (Key.size() == 32)
	{
		_wrkState[0] = IntUtils::BytesToLe32(_dstCode, 0);
		_wrkState[1] = IntUtils::BytesToLe32(Key, 0);
		_wrkState[2] = IntUtils::BytesToLe32(Key, 4);
		_wrkState[3] = IntUtils::BytesToLe32(Key, 8);
		_wrkState[4] = IntUtils::BytesToLe32(Key, 12);
		_wrkState[5] = IntUtils::BytesToLe32(_dstCode, 4);
		_wrkState[6] = IntUtils::BytesToLe32(Iv, 0);
		_wrkState[7] = IntUtils::BytesToLe32(Iv, 4);
		_wrkState[8] = IntUtils::BytesToLe32(_dstCode, 8);
		_wrkState[9] = IntUtils::BytesToLe32(Key, 16);
		_wrkState[10] = IntUtils::BytesToLe32(Key, 20);
		_wrkState[11] = IntUtils::BytesToLe32(Key, 24);
		_wrkState[12] = IntUtils::BytesToLe32(Key, 28);
		_wrkState[13] = IntUtils::BytesToLe32(_dstCode, 12);
	}
	else
	{
		_wrkState[0] = IntUtils::BytesToLe32(_dstCode, 0);
		_wrkState[1] = IntUtils::BytesToLe32(Key, 0);
		_wrkState[2] = IntUtils::BytesToLe32(Key, 4);
		_wrkState[3] = IntUtils::BytesToLe32(Key, 8);
		_wrkState[4] = IntUtils::BytesToLe32(Key, 12);
		_wrkState[5] = IntUtils::BytesToLe32(_dstCode, 4);
		_wrkState[6] = IntUtils::BytesToLe32(Iv, 0);
		_wrkState[7] = IntUtils::BytesToLe32(Iv, 4);
		_wrkState[8] = IntUtils::BytesToLe32(_dstCode, 8);
		_wrkState[9] = IntUtils::BytesToLe32(Key, 0);
		_wrkState[10] = IntUtils::BytesToLe32(Key, 4);
		_wrkState[11] = IntUtils::BytesToLe32(Key, 8);
		_wrkState[12] = IntUtils::BytesToLe32(Key, 12);
		_wrkState[13] = IntUtils::BytesToLe32(_dstCode, 12);
	}
}

// ** Processing ** //

void Salsa20::Increase(const std::vector<uint> &Counter, const unsigned int Size, std::vector<uint> &Vector)
{
	Vector = Counter;

	for (unsigned int i = 0; i < Size; i++)
		Increment(Vector);
}

void Salsa20::Increment(std::vector<uint> &Counter)
{
	if (++Counter[0] == 0)
		++Counter[1];
}

void Salsa20::Generate(const unsigned int Size, std::vector<uint> &Counter, std::vector<byte> &Output, const unsigned int OutOffset)
{
	unsigned int aln = Size - (Size % BLOCK_SIZE);
	unsigned int ctr = 0;

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

void Salsa20::ProcessBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!_isParallel || Output.size() < _parallelBlockSize)
	{
		// generate random
		Generate(Output.size(), _ctrVector, Output, 0);
		// output is input xor with random
		unsigned int sze = Output.size() - (Output.size() % BLOCK_SIZE);

		if (sze != 0)
			IntUtils::XORBLK(Input, 0, Output, 0, sze);

		// get the remaining bytes
		if (sze != Output.size())
		{
			for (unsigned int i = sze; i < Output.size(); ++i)
				Output[i] ^= Input[i];
		}
	}
	else
	{
		// parallel CTR processing //
		unsigned int cnkSize = (Output.size() / BLOCK_SIZE / _processorCount) * BLOCK_SIZE;
		unsigned int rndSize = cnkSize * _processorCount;
		unsigned int subSize = (cnkSize / BLOCK_SIZE);
		// create jagged array of 'sub counters'
		_threadVectors.resize(_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, _processorCount, [this, &Input, &Output, cnkSize, rndSize, subSize](unsigned int i)
		{
			std::vector<uint> &iv = _threadVectors[i];
			// offset counter by chunk size / block size
			this->Increase(_ctrVector, subSize * i, iv);
			// create random at offset position
			this->Generate(cnkSize, iv, Output, (i * cnkSize));
			// xor with input at offset
			IntUtils::XORBLK(Input, i * cnkSize, Output, i * cnkSize, cnkSize);
		});

		// last block processing
		if (rndSize < Output.size())
		{
			unsigned int fnlSize = Output.size() % rndSize;
			Generate(fnlSize, _threadVectors[_processorCount - 1], Output, rndSize);

			for (unsigned int i = rndSize; i < Output.size(); ++i)
				Output[i] ^= Input[i];
		}

		// copy the last counter position to class variable
		memcpy(&_ctrVector[0], &_threadVectors[_processorCount - 1][0], _ctrVector.size());
	}
}

void Salsa20::ProcessBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	unsigned int outSize = _isParallel ? (Output.size() - OutOffset) : BLOCK_SIZE;

	if (outSize < _parallelBlockSize)
	{
		// generate random
		Generate(outSize, _ctrVector, Output, OutOffset);
		// output is input xor with random
		unsigned int sze = outSize - (outSize % BLOCK_SIZE);

		if (sze != 0)
			IntUtils::XORBLK(Input, InOffset, Output, OutOffset, sze);

		// get the remaining bytes
		if (sze != outSize)
		{
			for (unsigned int i = sze; i < outSize; ++i)
				Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
	else
	{
		// parallel CTR processing //
		unsigned int cnkSize = _parallelBlockSize / _processorCount;
		unsigned int rndSize = cnkSize * _processorCount;
		unsigned int subSize = cnkSize / BLOCK_SIZE;

		// create jagged array of 'sub counters'
		_threadVectors.resize(_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, _processorCount, [this, &Input, InOffset, &Output, OutOffset, cnkSize, rndSize, subSize](unsigned int i)
		{
			std::vector<uint> &iv = _threadVectors[i];
			// offset counter by chunk size / block size
			this->Increase(_ctrVector, subSize * i, iv);
			// create random at offset position
			this->Generate(cnkSize, iv, Output, (i * cnkSize));
			// xor with input at offset
			IntUtils::XORBLK(Input, InOffset + (i * cnkSize), Output, OutOffset + (i * cnkSize), cnkSize);
		});

		// copy the last counter position to class variable
		memcpy(&_ctrVector[0], &_threadVectors[_processorCount - 1][0], _ctrVector.size());
	}
}

void Salsa20::ProcessBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset, const unsigned int Length)
{
	unsigned int outSize = Length;

	if (!_isParallel || outSize < _parallelBlockSize)
	{
		// generate random
		Generate(outSize, _ctrVector, Output, OutOffset);
		// output is input xor with random
		unsigned int sze = Length - (Length % BLOCK_SIZE);

		if (sze != 0)
			IntUtils::XORBLK(Input, InOffset, Output, OutOffset, sze);

		// get the remaining bytes
		if (sze != OutOffset + Length)
		{
			for (unsigned int i = sze; i < Output.size(); ++i)
				Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
	else
	{
		// parallel CTR processing //
		unsigned int cnkSize = (Length / BLOCK_SIZE / _processorCount) * BLOCK_SIZE;
		unsigned int rndSize = cnkSize * _processorCount;
		unsigned int subSize = (cnkSize / BLOCK_SIZE);

		// create jagged array of 'sub counters'
		_threadVectors.resize(_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, _processorCount, [this, &Input, InOffset, &Output, OutOffset, cnkSize, rndSize, subSize](unsigned int i)
		{
			std::vector<uint> &Vec = _threadVectors[i];
			// offset counter by chunk size / block size
			this->Increase(_ctrVector, subSize * i, Vec);
			// create random at offset position
			this->Generate(cnkSize, Vec, Output, (i * cnkSize));
			// xor with input at offset
			IntUtils::XORBLK(Input, InOffset + (i * cnkSize), Output, OutOffset + (i * cnkSize), cnkSize);
		});

		// last block processing
		if (rndSize < Length)
		{
			unsigned int fnlSize = Length % rndSize;
			Generate(fnlSize, _threadVectors[_processorCount - 1], Output, rndSize);

			for (unsigned int i = 0; i < fnlSize; ++i)
				Output[i + OutOffset + rndSize] ^= (byte)(Input[i + InOffset + rndSize]);
		}

		// copy the last counter position to class variable
		memcpy(&_ctrVector[0], &_threadVectors[_processorCount - 1][0], _ctrVector.size());
	}
}

void Salsa20::SalsaCore(std::vector<byte> &Output, unsigned int OutOffset, const std::vector<uint> &Counter)
{
	unsigned int ctr = 0;
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
		X4 ^= IntUtils::RotateLeft(X0 + X12, 7);
		X8 ^= IntUtils::RotateLeft(X4 + X0, 9);
		X12 ^= IntUtils::RotateLeft(X8 + X4, 13);
		X0 ^= IntUtils::RotateLeft(X12 + X8, 18);
		X9 ^= IntUtils::RotateLeft(X5 + X1, 7);
		X13 ^= IntUtils::RotateLeft(X9 + X5, 9);
		X1 ^= IntUtils::RotateLeft(X13 + X9, 13);
		X5 ^= IntUtils::RotateLeft(X1 + X13, 18);
		X14 ^= IntUtils::RotateLeft(X10 + X6, 7);
		X2 ^= IntUtils::RotateLeft(X14 + X10, 9);
		X6 ^= IntUtils::RotateLeft(X2 + X14, 13);
		X10 ^= IntUtils::RotateLeft(X6 + X2, 18);
		X3 ^= IntUtils::RotateLeft(X15 + X11, 7);
		X7 ^= IntUtils::RotateLeft(X3 + X15, 9);
		X11 ^= IntUtils::RotateLeft(X7 + X3, 13);
		X15 ^= IntUtils::RotateLeft(X11 + X7, 18);
		X1 ^= IntUtils::RotateLeft(X0 + X3, 7);
		X2 ^= IntUtils::RotateLeft(X1 + X0, 9);
		X3 ^= IntUtils::RotateLeft(X2 + X1, 13);
		X0 ^= IntUtils::RotateLeft(X3 + X2, 18);
		X6 ^= IntUtils::RotateLeft(X5 + X4, 7);
		X7 ^= IntUtils::RotateLeft(X6 + X5, 9);
		X4 ^= IntUtils::RotateLeft(X7 + X6, 13);
		X5 ^= IntUtils::RotateLeft(X4 + X7, 18);
		X11 ^= IntUtils::RotateLeft(X10 + X9, 7);
		X8 ^= IntUtils::RotateLeft(X11 + X10, 9);
		X9 ^= IntUtils::RotateLeft(X8 + X11, 13);
		X10 ^= IntUtils::RotateLeft(X9 + X8, 18);
		X12 ^= IntUtils::RotateLeft(X15 + X14, 7);
		X13 ^= IntUtils::RotateLeft(X12 + X15, 9);
		X14 ^= IntUtils::RotateLeft(X13 + X12, 13);
		X15 ^= IntUtils::RotateLeft(X14 + X13, 18);
		ctr -= 2;
	}

	IntUtils::Le32ToBytes(X0 + _wrkState[ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X1 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X2 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X3 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X4 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X5 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X6 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X7 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X8 + Counter[0], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X9 + Counter[1], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X10 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X11 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X12 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X13 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X14 + _wrkState[++ctr], Output, OutOffset); OutOffset += 4;
	IntUtils::Le32ToBytes(X15 + _wrkState[++ctr], Output, OutOffset);
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