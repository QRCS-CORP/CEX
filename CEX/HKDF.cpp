#include "HKDF.h"
#include "IntUtils.h"

NAMESPACE_GENERATOR

using CEX::Utility::IntUtils;

void HKDF::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_hashSize = 0;
		m_isInitialized = false;
		m_keySize = 0;
		m_generatedBytes = 0;

		IntUtils::ClearVector(m_currentT);
		IntUtils::ClearVector(m_digestInfo);
	}
}

size_t HKDF::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

size_t HKDF::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if ((Output.size() - Size) < OutOffset)
		throw CryptoGeneratorException("HKDF:Generate", "Output buffer too small!");
	if (m_generatedBytes + Size > 255 * m_hashSize)
		throw CryptoGeneratorException("HKDF:Generate", "HKDF may only be used for 255 * HashLen bytes of output");
#endif

	if (m_generatedBytes % m_hashSize == 0)
		Expand();

	// copy what is left in the buffer
	size_t toGenerate = Size;
	size_t posInT = m_generatedBytes % m_hashSize;
	size_t leftInT = m_hashSize - m_generatedBytes % m_hashSize;
	size_t toCopy = IntUtils::Min(leftInT, toGenerate);

	memcpy(&Output[OutOffset], &m_currentT[posInT], toCopy);
	m_generatedBytes += toCopy;
	toGenerate -= toCopy;
	OutOffset += toCopy;

	while (toGenerate != 0)
	{
		Expand();
		toCopy = IntUtils::Min(m_hashSize, toGenerate);
		memcpy(&Output[OutOffset], &m_currentT[0], toCopy);
		m_generatedBytes += toCopy;
		toGenerate -= toCopy;
		OutOffset += toCopy;
	}

	return Size;
}

void HKDF::Initialize(const std::vector<byte> &Ikm)
{
#if defined(CPPEXCEPTIONS_ENABLED)
	if (Ikm.size() < m_keySize)
		throw CryptoGeneratorException("DGCDrbg:Initialize", "Salt value is too small!");
#endif

	m_digestMac->Initialize(Ikm);
	m_generatedBytes = 0;
	m_currentT.resize(m_hashSize, 0);
	m_isInitialized = true;
}

void HKDF::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm)
{
	std::vector<byte> prk;
	Extract(Salt, Ikm, prk);
	m_digestMac->Initialize(prk);
	m_generatedBytes = 0;
	m_currentT.resize(m_hashSize, 0);
	m_isInitialized = true;
}

void HKDF::Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Nonce)
{
	std::vector<byte> prk;
	Extract(Salt, Ikm, prk);
	m_digestMac->Initialize(prk);
	m_digestInfo = Nonce;
	m_generatedBytes = 0;
	m_currentT.resize(m_hashSize, 0);
	m_isInitialized = true;
}

void HKDF::Update(const std::vector<byte> &Salt)
{
	Initialize(Salt);
}

//~~~Private~~~//

void HKDF::Extract(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, std::vector<byte> &Prk)
{
	Prk.resize(m_hashSize);
	m_digestMac->Initialize(Ikm);

	if (Salt.size() == 0)
	{
		std::vector<byte> zeros(m_hashSize, 0);
		m_digestMac->Initialize(zeros);
	}
	else
	{
		m_digestMac->Initialize(Salt);
	}

	m_digestMac->BlockUpdate(Ikm, 0, Ikm.size());
	m_digestMac->DoFinal(Prk, 0);
}

void HKDF::Expand()
{
	size_t n = m_generatedBytes / m_hashSize + 1;
#if defined(CPPEXCEPTIONS_ENABLED)
	if (n >= 256)
		throw CryptoGeneratorException("HKDF:Expand", "HKDF cannot generate more than 255 blocks of Digest output size!");
#endif

	if (m_generatedBytes != 0)
		m_digestMac->BlockUpdate(m_currentT, 0, m_hashSize);
	if (m_digestInfo.size() > 0)
		m_digestMac->BlockUpdate(m_digestInfo, 0, m_digestInfo.size());

	m_digestMac->Update((byte)n);
	m_digestMac->DoFinal(m_currentT, 0);
}

NAMESPACE_GENERATOREND
