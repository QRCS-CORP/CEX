#include "HKDF.h"
#include "IntUtils.h"

NAMESPACE_GENERATOR

void HKDF::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_hashSize = 0;
		_isInitialized = false;
		_keySize = 0;
		_generatedBytes = 0;

		CEX::Utility::IntUtils::ClearVector(_currentT);
		CEX::Utility::IntUtils::ClearVector(_digestInfo);
	}
}

size_t HKDF::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

size_t HKDF::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("HKDF:Generate", "Output buffer too small!");
	if (_generatedBytes + Size > 255 * _hashSize)
		throw CryptoGeneratorException("HKDF:Generate", "HKDF may only be used for 255 * HashLen bytes of output");

	if (_generatedBytes % _hashSize == 0)
		ExpandNext();

	// copy what is left in the buffer
	size_t toGenerate = Size;
	size_t posInT = _generatedBytes % _hashSize;
	size_t leftInT = _hashSize - _generatedBytes % _hashSize;
	size_t toCopy = CEX::Utility::IntUtils::Min(leftInT, toGenerate);

	memcpy(&Output[OutOffset], &_currentT[posInT], toCopy);
	_generatedBytes += toCopy;
	toGenerate -= toCopy;
	OutOffset += toCopy;

	while (toGenerate != 0)
	{
		ExpandNext();
		toCopy = CEX::Utility::IntUtils::Min(_hashSize, toGenerate);
		memcpy(&Output[OutOffset], &_currentT[0], toCopy);
		_generatedBytes += toCopy;
		toGenerate -= toCopy;
		OutOffset += toCopy;
	}

	return Size;
}

void HKDF::Initialize(const std::vector<byte> &Salt)
{
	if (Salt.size() < _keySize)
		throw CryptoGeneratorException("DGCDrbg:Initialize", "Salt value is too small!");

	_digestMac->Initialize(Salt);
	_generatedBytes = 0;
	_currentT.resize(_hashSize, 0);
	_isInitialized = true;
}

void HKDF::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm)
{
	std::vector<byte> prk;
	Extract(Salt, Ikm, prk);
	_digestMac->Initialize(prk);
	_generatedBytes = 0;
	_currentT.resize(_hashSize, 0);
	_isInitialized = true;
}

void HKDF::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Info)
{
	std::vector<byte> prk;
	Extract(Salt, Ikm, prk);
	_digestMac->Initialize(prk);
	_digestInfo = Info;
	_generatedBytes = 0;
	_currentT.resize(_hashSize, 0);
	_isInitialized = true;
}

void HKDF::Update(const std::vector<byte> &Salt)
{
	Initialize(Salt);
}

// *** Protected *** //

void HKDF::Extract(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, std::vector<byte> &Prk)
{
	Prk.resize(_hashSize);

	_digestMac->Initialize(Ikm);

	if (Salt.size() == 0)
	{
		std::vector<byte> zeros(_hashSize, 0);
		_digestMac->Initialize(zeros);
	}
	else
	{
		_digestMac->Initialize(Salt);
	}

	_digestMac->BlockUpdate(Ikm, 0, Ikm.size());
	_digestMac->DoFinal(Prk, 0);
}

void HKDF::ExpandNext()
{
	size_t n = _generatedBytes / _hashSize + 1;

	if (n >= 256)
		throw CryptoGeneratorException("HKDF:ExpandNext", "HKDF cannot generate more than 255 blocks of HashLen size");

	// special case for T(0): T(0) is empty, so no update
	if (_generatedBytes != 0)
		_digestMac->BlockUpdate(_currentT, 0, _hashSize);
	if (_digestInfo.size() > 0)
		_digestMac->BlockUpdate(_digestInfo, 0, _digestInfo.size());

	_digestMac->Update((byte)n);
	_digestMac->DoFinal(_currentT, 0);
}

NAMESPACE_GENERATOREND
