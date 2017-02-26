#include "SymmetricKeyGenerator.h"
#include "CSP.h"
#include "DigestFromName.h"
#include "HMAC.h"
#include "IntUtils.h"
#include "ProviderFromName.h"

NAMESPACE_KEYSYMMETRIC

//~~~Constructor~~~//

SymmetricKeyGenerator::SymmetricKeyGenerator(Digests DigestType, Providers ProviderType)
	:
	m_dgtType(DigestType),
	m_isDestroyed(false),
	m_pvdType(ProviderType)
{
	// initialize the provider
	Reset();
}

SymmetricKeyGenerator::~SymmetricKeyGenerator()
{
	Destroy();
}

//~~~Public Functions~~~//

void SymmetricKeyGenerator::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_dgtType = Digests::None;
		m_pvdType = Providers::None;

		if (m_pvdEngine != 0)
			delete m_pvdEngine;
	}
}

SymmetricKey SymmetricKeyGenerator::GetSymmetricKey(SymmetricKeySize KeySize)
{
	if (KeySize.KeySize() == 0)
	{
		throw CryptoGeneratorException("SymmetricKeyGenerator::GetKey", "The key size can not be zero!");
	}
	else
	{
		if (KeySize.NonceSize() != 0)
		{
			if (KeySize.InfoSize() != 0)
				return SymmetricKey(Generate(KeySize.KeySize()), Generate(KeySize.NonceSize()), Generate(KeySize.InfoSize()));
			else
				return SymmetricKey(Generate(KeySize.KeySize()), Generate(KeySize.NonceSize()));
		}
		else
		{
			return SymmetricKey(Generate(KeySize.KeySize()));
		}
	}
}

SymmetricSecureKey SymmetricKeyGenerator::GetSecureKey(SymmetricKeySize KeySize)
{
	if (KeySize.KeySize() == 0)
	{
		throw CryptoGeneratorException("SymmetricKeyGenerator::GetSecureKey", "The key size can not be zero!");
	}
	else
	{
		if (KeySize.NonceSize() != 0)
		{
			if (KeySize.InfoSize() != 0)
				return SymmetricSecureKey(Generate(KeySize.KeySize()), Generate(KeySize.NonceSize()), Generate(KeySize.InfoSize()));
			else
				return SymmetricSecureKey(Generate(KeySize.KeySize()), Generate(KeySize.NonceSize()));
		}
		else
		{
			return SymmetricSecureKey(Generate(KeySize.KeySize()));
		}
	}
}

void SymmetricKeyGenerator::GetBytes(std::vector<byte> &Output)
{
	std::vector<byte> rnd = Generate(Output.size());
	memcpy(&Output[0], &rnd[0], rnd.size());
}

std::vector<byte> SymmetricKeyGenerator::GetBytes(size_t Size)
{
	return Generate(Size);
}

void SymmetricKeyGenerator::Reset()
{
	// reset provider engine
	if (m_pvdEngine != 0)
		delete m_pvdEngine;

	try
	{
		m_pvdEngine = Helper::ProviderFromName::GetInstance(m_pvdType);
	}
	catch (...) 
	{ 
	}

	// if provider is unavailable, default to system crypto provider
	if (m_pvdEngine == 0 || !m_pvdEngine->IsAvailable())
	{
		delete m_pvdEngine;
		m_pvdEngine = Helper::ProviderFromName::GetInstance(Providers::CSP);
	}
}

//~~~Private Functions~~~//

std::vector<byte> SymmetricKeyGenerator::Generate(size_t KeySize)
{
	if (KeySize == 0)
		return std::vector<byte>(0);

	std::vector<byte> key(KeySize);
	size_t keyLen = KeySize;
	size_t blkOff = 0;

	do
	{
		std::vector<byte> rnd = GenerateBlock();
		size_t alnLen = Utility::IntUtils::Min(keyLen, rnd.size());
		memcpy(&key[blkOff], &rnd[0], alnLen);
		keyLen -= alnLen;
		blkOff += alnLen;
	} 
	while (keyLen != 0);

	return key;
}

std::vector<byte> SymmetricKeyGenerator::GenerateBlock()
{
	// seed size is 2x mac input block size less finalizer padding
	const size_t BLKSZE = Helper::DigestFromName::GetBlockSize(m_dgtType);
	size_t seedLen = (BLKSZE * 2) - Helper::DigestFromName::GetPaddingSize(m_dgtType);
	std::vector<byte> seed(seedLen);

	// generate the seed
	m_pvdEngine->GetBytes(seed);

	// get the hmac key from system entropy provider
	std::vector<byte> key(BLKSZE);
	Provider::CSP pvd;
	pvd.GetBytes(key);

	// condition random bytes with an hmac
	Mac::HMAC mac(m_dgtType);
	SymmetricKey kp(key);
	mac.Initialize(kp);
	std::vector<byte> output(mac.MacSize());
	mac.Compute(seed, output);

	return output;
}

NAMESPACE_KEYSYMMETRICEND