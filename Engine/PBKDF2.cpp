#include "PBKDF2.h"
#include "IntUtils.h"

NAMESPACE_GENERATOR

using CEX::Utility::IntUtils;

void PBKDF2::Destroy()
{
	if (!_isDestroyed)
	{
		_blockSize = 0;
		_hashSize = 0;
		_isInitialized = false;
		_prcIterations = 0;

		IntUtils::ClearVector(_macKey);
		IntUtils::ClearVector(_macSalt);

		_isDestroyed = true;
	}
}

unsigned int PBKDF2::Generate(std::vector<byte> &Output)
{
	GenerateKey(Output, 0, Output.size());

	return Output.size();
}

unsigned int PBKDF2::Generate(std::vector<byte> &Output, unsigned int OutOffset, unsigned int Size)
{
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("PBKDF2:Generate", "Output buffer too small!");

	GenerateKey(Output, OutOffset, Size);

	return Size;
}

void PBKDF2::Initialize(const std::vector<byte> &Salt)
{
	if (Salt.size() < _hashSize * 2)
		throw CryptoGeneratorException("PBKDF2:Initialize", "Salt size is too small; must be a minumum of digest return size!");

	_macKey.resize(_hashSize);
	memcpy(&_macKey[0], &Salt[0], _hashSize);
	_macSalt.resize(Salt.size() - _hashSize);
	memcpy(&_macSalt[0], &Salt[_hashSize], Salt.size() - _hashSize);

	_isInitialized = true;
}

void PBKDF2::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm)
{
	if (Salt.size() < _blockSize)
		throw CryptoGeneratorException("PBKDF2:Initialize", "Salt size is too small; must be a minumum of digest return size!");
	if (Ikm.size() < _hashSize)
		throw CryptoGeneratorException("PBKDF2:Initialize", "IKM size is too small; must be a minumum of digest block size!");

	// clone iv and salt
	_macKey.resize(Ikm.size());
	_macSalt.resize(Salt.size());

	if (_macKey.size() > 0)
		memcpy(&_macKey[0], &Ikm[0], Ikm.size());
	if (_macSalt.size() > 0)
		memcpy(&_macSalt[0], &Salt[0], Salt.size());

	_isInitialized = true;
}

void PBKDF2::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Nonce)
{
	if (Salt.size() + Nonce.size() < _blockSize)
		throw CryptoGeneratorException("PBKDF2:Initialize", "Salt size is too small; must be a minumum of digest return size!");
	if (Ikm.size() < _hashSize)
		throw CryptoGeneratorException("PBKDF2:Initialize", "IKM with Nonce size is too small; combined must be a minumum of digest block size!");

	_macKey.resize(Ikm.size());
	_macSalt.resize(Salt.size() + Nonce.size());

	if (_macKey.size() > 0)
		memcpy(&_macKey[0], &Ikm[0], Ikm.size());
	if (_macSalt.size() > 0)
		memcpy(&_macSalt[0], &Salt[0], Salt.size());
	if (Nonce.size() > 0)
		memcpy(&_macSalt[Salt.size()], &Nonce[0], Nonce.size());

	_isInitialized = true;
}

void PBKDF2::Update(const std::vector<byte> &Salt)
{
	if (Salt.size() == 0)
		throw CryptoGeneratorException("PBKDF2:Update", "Salt is too small!");

	Initialize(Salt);
}

// *** Protected *** //

unsigned int PBKDF2::GenerateKey(std::vector<byte> &Output, unsigned int OutOffset, unsigned int Size)
{
	int diff = Size % _hashSize;
	int max = Size / _hashSize;
	int ctr = 0;
	std::vector<byte> buffer(4);
	std::vector<byte> outBytes(Size);

	for (ctr = 0; ctr < max; ctr++)
	{
		IntToOctet(buffer, ctr + 1);
		Process(buffer, outBytes, ctr * _hashSize);
	}

	if (diff > 0)
	{
		IntToOctet(buffer, ctr + 1);
		std::vector<byte> rem(_hashSize);
		Process(buffer, rem, 0);
		memcpy(&outBytes[outBytes.size() - diff], &rem[0], diff);
	}

	memcpy(&Output[OutOffset], &outBytes[0], outBytes.size());

	return Size;
}

void PBKDF2::IntToOctet(std::vector<byte> &Output, unsigned int Counter)
{
	Output[0] = (byte)((unsigned int)Counter >> 24);
	Output[1] = (byte)((unsigned int)Counter >> 16);
	Output[2] = (byte)((unsigned int)Counter >> 8);
	Output[3] = (byte)Counter;
}

void PBKDF2::Process(std::vector<byte> Input, std::vector<byte> &Output, unsigned int OutOffset)
{
	std::vector<byte> state(_hashSize);

	_digestMac->Initialize(_macKey);

	if (_macSalt.size() != 0)
		_digestMac->BlockUpdate(_macSalt, 0, _macSalt.size());

	_digestMac->BlockUpdate(Input, 0, Input.size());
	_digestMac->DoFinal(state, 0);

	memcpy(&Output[OutOffset], &state[0], state.size());

	for (int count = 1; count != _prcIterations; count++)
	{
		_digestMac->Initialize(_macKey);
		_digestMac->BlockUpdate(state, 0, state.size());
		_digestMac->DoFinal(state, 0);

		for (int j = 0; j != state.size(); j++)
			Output[OutOffset + j] ^= state[j];
	}
}

NAMESPACE_GENERATOREND
