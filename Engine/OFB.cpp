#include "OFB.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

void OFB::Destroy()
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

		CEX::Utility::IntUtils::ClearVector(_ofbIv);
		CEX::Utility::IntUtils::ClearVector(_ofbBuffer);
	}
}

void OFB::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
	std::vector<byte> iv = KeyParam.IV();
	unsigned int diff = _ofbIv.size() - iv.size();
	_blockCipher->Initialize(true, KeyParam);

	if (iv.size() < _ofbIv.size())
	{
		// prepend the supplied IV with zeros per FIPS PUB 81
		memcpy(&_ofbIv[_ofbIv.size() - iv.size()], &iv[0], iv.size());

		for (unsigned int i = 0; i < _ofbIv.size() - iv.size(); i++)
			_ofbIv[i] = 0;
	}
	else
	{
		memcpy(&_ofbIv[0], &iv[0], _ofbIv.size());
	}

	_isEncryption = Encryption;
	_isInitialized = true;
}

void OFB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	ProcessBlock(Input, 0, Output, 0);
}

void OFB::Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	ProcessBlock(Input, InOffset, Output, OutOffset);
}

void OFB::ProcessBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	_blockCipher->Transform(_ofbIv, 0, _ofbBuffer, 0);

	// xor the _ofbIv with the plaintext producing the cipher text and the next Input block
	for (unsigned int i = 0; i < _blockSize; i++)
		Output[OutOffset + i] = (byte)(_ofbBuffer[i] ^ Input[InOffset + i]);

	// change over the Input block
	if (_ofbIv.size() - _blockSize > 0)
		memcpy(&_ofbIv[0], &_ofbIv[_blockSize], _ofbIv.size() - _blockSize);

	memcpy(&_ofbIv[_ofbIv.size() - _blockSize], &_ofbBuffer[0], _blockSize);
}

void OFB::SetScope()
{
	_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (_processorCount % 2 != 0)
		_processorCount--;
	if (_processorCount > 1)
		_isParallel = true;
}

NAMESPACE_MODEEND