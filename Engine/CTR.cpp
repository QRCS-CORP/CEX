#include "CTR.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

void CTR::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_blockSize = 0;
		_isEncryption = false;
		_isInitialized = false;
		_processorCount = 0;
		_isParallel = false;
		_parallelBlockSize = 0;

		CEX::Utility::IntUtils::ClearVector(_ctrVector);
		CEX::Utility::IntUtils::ClearArray(_threadVectors);
	}
}

void CTR::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
	_blockCipher->Initialize(true, KeyParam);
	_ctrVector = KeyParam.IV();
	_isEncryption = Encryption;
	_isInitialized = true;
}

void CTR::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	ProcessBlock(Input, Output);
}

void CTR::Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	ProcessBlock(Input, InOffset, Output, OutOffset);
}

void CTR::Generate(const unsigned int Length, std::vector<byte> &Counter, std::vector<byte> &Output, const unsigned int OutOffset)
{
	unsigned int aln = Length - (Length % _blockSize);
	unsigned int ctr = 0;

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
		unsigned int fnlSize = Length % _blockSize;
		memcpy(&Output[OutOffset + (Length - fnlSize)], &outputBlock[0], fnlSize);
		Increment(Counter);
	}
}

void CTR::ProcessBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!_isParallel || Output.size() < _parallelBlockSize)
	{
		// generate random
		Generate(Output.size(), _ctrVector, Output, 0);
		// output is input xor with random
		unsigned int sze = Output.size() - (Output.size() % _blockCipher->BlockSize());

		if (sze != 0)
			CEX::Utility::IntUtils::XORBLK(Input, 0, Output, 0, sze);

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
		const unsigned int cnkSize = (Output.size() / _blockSize / _processorCount) * _blockSize;
		const unsigned int rndSize = cnkSize * _processorCount;
		const unsigned int subSize = (cnkSize / _blockSize);
		// create jagged array of 'sub counters'
		_threadVectors.resize(_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, _processorCount, [this, &Input, &Output, cnkSize, rndSize, subSize](unsigned int i)
		{
			std::vector<byte> &thdVec = _threadVectors[i];
			// offset counter by chunk size / block size
			this->Increase(_ctrVector, subSize * i, thdVec);
			// create random at offset position
			this->Generate(cnkSize, thdVec, Output, (i * cnkSize));
			// xor the block
			CEX::Utility::IntUtils::XORBLK(Input, i * cnkSize, Output, i * cnkSize, cnkSize);
		});

		// last block processing
		if (rndSize < Output.size())
		{
			unsigned int fnlSize = Output.size() % rndSize;
			Generate(fnlSize, _threadVectors[_processorCount - 1], Output, rndSize);

			for (unsigned int i = rndSize; i < Output.size(); i++)
				Output[i] ^= Input[i];
		}

		// copy the last counter position to class variable
		memcpy(&_ctrVector[0], &_threadVectors[_processorCount - 1][0], _ctrVector.size());
	}
}

void CTR::ProcessBlock(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
{
	unsigned int outSize = _isParallel ? (Output.size() - OutOffset) : _blockCipher->BlockSize();

	// process either a partial parallel or linear block
	if (outSize < _parallelBlockSize)
	{
		// generate random
		Generate(outSize, _ctrVector, Output, OutOffset);
		// process block aligned
		unsigned int sze = outSize - (outSize % _blockCipher->BlockSize());

		if (sze != 0)
			CEX::Utility::IntUtils::XORBLK(Input, InOffset, Output, OutOffset, sze);

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
		const unsigned int cnkSize = _parallelBlockSize / _processorCount;
		const unsigned int rndSize = cnkSize * _processorCount;
		const unsigned int subSize = (cnkSize / _blockSize);
		// create jagged array of 'sub counters'
		_threadVectors.resize(_processorCount);

		CEX::Utility::ParallelUtils::ParallelFor(0, _processorCount, [this, &Input, InOffset, &Output, OutOffset, cnkSize, rndSize, subSize](unsigned int i)
		{
			std::vector<byte> &thdVec = _threadVectors[i];
			// offset counter by chunk size / block size
			this->Increase(_ctrVector, subSize * i, thdVec);
			// create random at offset position
			this->Generate(cnkSize, thdVec, Output, (i * cnkSize));
			// xor with input at offset
			CEX::Utility::IntUtils::XORBLK(Input, InOffset + (i * cnkSize), Output, OutOffset + (i * cnkSize), cnkSize);
		});

		// copy the last counter position to class variable
		memcpy(&_ctrVector[0], &_threadVectors[_processorCount - 1][0], _ctrVector.size());
	}
}

void CTR::Increment(std::vector<byte> &Counter)
{
	int i = Counter.size();
	while (--i >= 0 && ++Counter[i] == 0) {}
}

void CTR::Increase(const std::vector<byte> &Counter, const unsigned int Size, std::vector<byte> &Buffer)
{
	if (Buffer.size() != Counter.size())
		Buffer.resize(Counter.size(), 0);

	int carry = 0;
	int offset = Buffer.size() - 1;
	const int cntSize = sizeof(Size);
	std::vector<byte> cnt(cntSize, 0);
	memcpy(&cnt[0], &Size, cntSize);
	byte osrc, odst, ndst;
	memcpy(&Buffer[0], &Counter[0], Counter.size());

	for (unsigned int i = offset; i > 0; i--)
	{
		odst = Buffer[i];
		osrc = offset - i < cnt.size() ? cnt[offset - i] : (byte)0;
		ndst = (byte)(odst + osrc + carry);
		carry = ndst < odst ? 1 : 0;
		Buffer[i] = ndst;
	}
}

void CTR::SetScope()
{
	_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (_processorCount % 2 != 0)
		_processorCount--;
	if (_processorCount > 1)
		_isParallel = true;

	// calc default parallel block size as n * 64kb
	_parallelBlockSize = _processorCount * PARALLEL_DEFBLOCK;
}

NAMESPACE_MODEEND
