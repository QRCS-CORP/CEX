#include "ECB.h"
#include "IntUtils.h"
#include "ParallelUtils.h"

NAMESPACE_MODE

void ECB::DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	_blockCipher->DecryptBlock(Input, Output);
}

void ECB::DecryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	_blockCipher->DecryptBlock(Input, InOffset, Output, OutOffset);
}

void ECB::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_blockSize = 0;
		_isEncryption = false;
		_isInitialized = false;
		_isParallel = false;
		_parallelBlockSize = 0;
	}
}

void ECB::EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	_blockCipher->EncryptBlock(Input, Output);
}

void ECB::EncryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	_blockCipher->EncryptBlock(Input, InOffset, Output, OutOffset);
}

void ECB::Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam)
{
	_blockCipher->Initialize(Encryption, KeyParam);
	_isEncryption = Encryption;
	_isInitialized = true;
}

void ECB::Transform(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (_isEncryption)
		EncryptBlock(Input, Output);
	else
		DecryptBlock(Input, Output);
}

void ECB::Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset)
{
	if (_isEncryption)
		EncryptBlock(Input, InOffset, Output, OutOffset);
	else
		DecryptBlock(Input, InOffset, Output, OutOffset);
}

void ECB::SetScope()
{
	_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	if (_processorCount % 2 != 0)
		_processorCount--;
	if (_processorCount > 1)
		_isParallel = true;
}

NAMESPACE_MODEEND