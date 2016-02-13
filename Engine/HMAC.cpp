#include "HMAC.h"
#include "IntUtils.h"

NAMESPACE_MAC

void HMAC::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (InOffset + Length > Input.size())
		throw CryptoMacException("HMAC:BlockUpdate", "The Input buffer is too short!");

	_msgDigest->BlockUpdate(Input, InOffset, Length);
}

void HMAC::ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(_msgDigest->DigestSize());
	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
}

void HMAC::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_blockSize = 0;
		_digestSize = 0;
		_isInitialized = false;
		CEX::Utility::IntUtils::ClearVector(_inputPad);
		CEX::Utility::IntUtils::ClearVector(_outputPad);
	}
}

size_t HMAC::DoFinal(std::vector<byte> &Output, size_t OutOffset)
{
	if (Output.size() - OutOffset < _msgDigest->DigestSize())
		throw CryptoMacException("HMAC:DoFinal", "The Output buffer is too short!");

	std::vector<byte> tmpv(_digestSize, 0);

	_msgDigest->DoFinal(tmpv, 0);
	_msgDigest->BlockUpdate(_outputPad, 0, _outputPad.size());
	_msgDigest->BlockUpdate(tmpv, 0, tmpv.size());
	size_t msgLen = _msgDigest->DoFinal(Output, OutOffset);
	_msgDigest->BlockUpdate(_inputPad, 0, _inputPad.size());
	Reset();

	return msgLen;
}

void HMAC::Initialize(const std::vector<byte> &MacKey, const std::vector<byte> &IV)
{
	_msgDigest->Reset();
	size_t keyLength = MacKey.size() + IV.size();

	// combine and compress
	if (IV.size() > 0)
	{
		std::vector<byte> tmpKey(keyLength, 0);
		memcpy(&tmpKey[0], &MacKey[0], MacKey.size());
		memcpy(&tmpKey[MacKey.size()], &IV[0], IV.size());
		_msgDigest->BlockUpdate(tmpKey, 0, tmpKey.size());
		_msgDigest->DoFinal(_inputPad, 0);
		keyLength = _digestSize;
	}
	// compress to digest size
	else if (MacKey.size() > _blockSize)
	{
		_msgDigest->BlockUpdate(MacKey, 0, MacKey.size());
		_msgDigest->DoFinal(_inputPad, 0);
		keyLength = _digestSize;
	}
	else
	{
		memcpy(&_inputPad[0], &MacKey[0], keyLength);
	}

	if (_blockSize - keyLength > 0)
		memset(&_inputPad[keyLength], (byte)0, _blockSize - keyLength);

	memcpy(&_outputPad[0], &_inputPad[0], _blockSize);
	XOr(_inputPad, IPAD);
	XOr(_outputPad, OPAD);

	// initialise the digest
	_msgDigest->BlockUpdate(_inputPad, 0, _inputPad.size());
	_isInitialized = true;
}

void HMAC::Reset()
{
	_msgDigest->Reset();
	_msgDigest->BlockUpdate(_inputPad, 0, _inputPad.size());
}

void HMAC::Update(byte Input)
{
	_msgDigest->Update(Input);
}

NAMESPACE_MACEND
