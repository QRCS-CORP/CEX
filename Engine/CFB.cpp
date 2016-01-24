#include "CFB.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

using CEX::Utility::IntUtils;
using CEX::Utility::ParallelUtils;

void CFB::Destroy()
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

		IntUtils::ClearVector(_cfbIv);
		IntUtils::ClearVector(_cfbBuffer);
		IntUtils::ClearArray(_threadVectors);
	}
}

void CFB::Initialize(bool Encryption, const KeyParams &KeyParam)
{
	std::vector<byte> iv = KeyParam.IV();
	unsigned int diff = _cfbIv.size() - iv.size();

	memcpy(&_cfbIv[diff], &iv[0], iv.size());
	memset(&_cfbIv[0], 0, diff);

	_blockCipher->Initialize(true, KeyParam);
	_isEncryption = Encryption;
	_isInitialized = true;
}

void CFB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (_isEncryption)
	{
		EncryptBlock(Input, Output);
	}
	else
	{
		if (_isParallel)
			ParallelDecrypt(Input, Output);
		else
			DecryptBlock(Input, Output);
	}
}

void CFB::Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	if (_isEncryption)
	{
		EncryptBlock(Input, InOffset, Output, OutOffset);
	}
	else
	{
		if (_isParallel)
			ParallelDecrypt(Input, InOffset, Output, OutOffset);
		else
			DecryptBlock(Input, InOffset, Output, OutOffset);
	}
}

void CFB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	_blockCipher->Transform(_cfbIv, 0, Output, 0);

	// change over the input block
	if (_cfbIv.size() - _blockSize > 0)
		memcpy(&_cfbIv[0], &_cfbIv[_blockSize], _cfbIv.size() - _blockSize);

	memcpy(&_cfbIv[_cfbIv.size() - _blockSize], &Input[0], _blockSize);

	// XOR the IV with the ciphertext producing the plaintext
	for (unsigned int i = 0; i < _blockSize; i++)
		Output[i] ^= Input[i];
}

void CFB::DecryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	_blockCipher->Transform(_cfbIv, 0, Output, OutOffset);

	// change over the input block
	if (_cfbIv.size() - _blockSize > 0)
		memcpy(&_cfbIv[0], &_cfbIv[_blockSize], _cfbIv.size() - _blockSize);

	memcpy(&_cfbIv[_cfbIv.size() - _blockSize], &Input[InOffset], _blockSize);

	// XOR the IV with the ciphertext producing the plaintext
	for (unsigned int i = 0; i < _blockSize; i++)
		Output[OutOffset + i] ^= Input[InOffset + i];
}

void CFB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	_blockCipher->Transform(_cfbIv, 0, Output, 0);

	// XOR the IV with the plaintext producing the ciphertext
	for (unsigned int i = 0; i < _blockSize; i++)
		Output[i] ^= Input[i];

	// change over the input block
	if (_cfbIv.size() - _blockSize > 0)
		memcpy(&_cfbIv[0], &_cfbIv[_blockSize], _cfbIv.size() - _blockSize);

	memcpy(&_cfbIv[_cfbIv.size() - _blockSize], &Output[0], _blockSize);
}

void CFB::EncryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	_blockCipher->Transform(_cfbIv, 0, Output, OutOffset);

	// XOR the IV with the plaintext producing the ciphertext
	for (unsigned int i = 0; i < _blockSize; i++)
		Output[OutOffset + i] ^= Input[InOffset + i];

	// change over the input block.
	if (_cfbIv.size() - _blockSize > 0)
		memcpy(&_cfbIv[0], &_cfbIv[_blockSize], _cfbIv.size() - _blockSize);

	memcpy(&_cfbIv[_cfbIv.size() - _blockSize], &Output[OutOffset], _blockSize);
}

void CFB::ParallelDecrypt(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (Output.size() < _parallelBlockSize)
	{
		unsigned int blocks = Output.size() / _blockSize;

		// output is input xor with random
		for (unsigned int i = 0; i < blocks; i++)
			DecryptBlock(Input, i * _blockSize, Output, i * _blockSize);
	}
	else
	{
		// parallel CFB decryption
		unsigned int cnkSize = _parallelBlockSize / _processorCount;
		const unsigned int blkSize = _blockSize;
		unsigned int blkCount = (cnkSize / blkSize);

		_threadVectors.resize(_processorCount);

		for (unsigned int i = 0; i < _processorCount; i++)
		{
			_threadVectors[i].resize(blkSize, 0);

			// get the first iv
			if (i != 0)
				memcpy(&_threadVectors[i][0], &Input[(i * cnkSize) - blkSize], blkSize);
			else
				memcpy(&_threadVectors[i][0], &_cfbIv[0], blkSize);
		}

		ParallelUtils::ParallelFor(0, _processorCount, [this, &Input, &Output, cnkSize, blkCount, blkSize](unsigned int i)
		{
			std::vector<byte> &thdVec = _threadVectors[i];
			this->ProcessDecrypt(Input, i * cnkSize, Output, i * cnkSize, thdVec, blkCount);
		});

		// copy the last vector to class variable
		memcpy(&_cfbIv[0], &_threadVectors[_processorCount - 1][0], _cfbIv.size());
	}
}

void CFB::ParallelDecrypt(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	if ((Output.size() - OutOffset) < _parallelBlockSize)
	{
		unsigned int blocks = (Output.size() - OutOffset) / _blockSize;

		// output is input xor with random
		for (unsigned int i = 0; i < blocks; i++)
			DecryptBlock(Input, (i * _blockSize) + InOffset, Output, (i * _blockSize) + OutOffset);
	}
	else
	{
		// parallel CFB decryption //
		unsigned int cnkSize = _parallelBlockSize / _processorCount;
		const unsigned int blkSize = _blockSize;
		unsigned int blkCount = (cnkSize / blkSize);

		_threadVectors.resize(_processorCount);

		for (unsigned int i = 0; i < _processorCount; i++)
		{
			_threadVectors[i].resize(blkSize, 0);

			// get the first iv 
			if (i != 0)
				memcpy(&_threadVectors[i][0], &Input[(InOffset + (i * cnkSize) - blkSize)], blkSize);
			else
				memcpy(&_threadVectors[i][0], &_cfbIv[0], blkSize);
		}

		ParallelUtils::ParallelFor(0, _processorCount, [this, &Input, InOffset, &Output, OutOffset, cnkSize, blkCount, blkSize](unsigned int i)
		{
			std::vector<byte> &thdVec = _threadVectors[i];
			this->ProcessDecrypt(Input, InOffset + i * cnkSize, Output, OutOffset + i * cnkSize, thdVec, blkCount);
		});

		// copy the last vector to class variable 
		memcpy(&_cfbIv[0], &_threadVectors[_processorCount - 1][0], _cfbIv.size());
	}
}

void CFB::ProcessDecrypt(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset, std::vector<byte> &Iv, const unsigned int BlockCount)
{
	for (unsigned int i = 0; i < BlockCount; i++)
	{ 
		_blockCipher->Transform(Iv, 0, Output, OutOffset);

		// change over the input block
		if (Iv.size() - _blockSize > 0)
			memcpy(&Iv[0], &Iv[_blockSize], Iv.size() - _blockSize);

		memcpy(&Iv[Iv.size() - _blockSize], &Input[InOffset], _blockSize);

		// XOR the IV with the ciphertext producing the plaintext
		for (unsigned int i = 0; i < _blockSize; i++)
			Output[OutOffset + i] ^= Input[InOffset + i];

		InOffset += Iv.size();
		OutOffset += Iv.size();
	}
}

void CFB::SetScope()
{
	_processorCount = ParallelUtils::ProcessorCount();
	if (_processorCount % 2 != 0)
		_processorCount--;
	if (_processorCount > 1)
		_isParallel = true;

	// calc default parallel block size as n * 64kb
	_parallelBlockSize = _processorCount * PARALLEL_DEFBLOCK;
}

NAMESPACE_MODEEND