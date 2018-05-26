#include "SymmetricKeyGenerator.h"
#include "CSP.h"
#include "DigestFromName.h"
#include "HMAC.h"
#include "IntUtils.h"
#include "ProviderFromName.h"

NAMESPACE_SYMMETRICKEY

//~~~Constructor~~~//

SymmetricKeyGenerator::SymmetricKeyGenerator(Digests DigestType, Providers ProviderType)
	:
	m_dgtType(DigestType != Digests::None ? DigestType :
		throw CryptoGeneratorException("SymmetricKeyGenerator::Ctor", "The digest type can not be none!")),
	m_isDestroyed(false),
	m_pvdEngine(ProviderType != Providers::None ? Helper::ProviderFromName::GetInstance(m_pvdType) : 
		throw CryptoGeneratorException("SymmetricKeyGenerator::Ctor", "The provider type can not be none!")),
	m_pvdType(ProviderType)
{
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
		{
			m_pvdEngine.reset(nullptr);
		}
	}
}

SymmetricKey* SymmetricKeyGenerator::GetSymmetricKey(SymmetricKeySize KeySize)
{
	if (KeySize.KeySize() == 0)
	{
		throw CryptoGeneratorException("SymmetricKeyGenerator::GetKey", "The key size can not be zero!");
	}
	else
	{
		SymmetricKey* key;

		if (KeySize.NonceSize() != 0)
		{
			if (KeySize.InfoSize() != 0)
			{
				key = new SymmetricKey(Generate(KeySize.KeySize()), Generate(KeySize.NonceSize()), Generate(KeySize.InfoSize()));

			}
			else
			{
				key = new SymmetricKey(Generate(KeySize.KeySize()), Generate(KeySize.NonceSize()));
			}
		}
		else
		{
			key = new SymmetricKey(Generate(KeySize.KeySize()));
		}

		return key;
	}
}

SymmetricSecureKey* SymmetricKeyGenerator::GetSecureKey(SymmetricKeySize KeySize)
{
	if (KeySize.KeySize() == 0)
	{
		throw CryptoGeneratorException("SymmetricKeyGenerator::GetSecureKey", "The key size can not be zero!");
	}
	else
	{
		SymmetricSecureKey* key;

		if (KeySize.NonceSize() != 0)
		{
			if (KeySize.InfoSize() != 0)
			{
				key = new SymmetricSecureKey(Generate(KeySize.KeySize()), Generate(KeySize.NonceSize()), Generate(KeySize.InfoSize()));
			}
			else
			{
				key = new SymmetricSecureKey(Generate(KeySize.KeySize()), Generate(KeySize.NonceSize()));
			}
		}
		else
		{
			key = new SymmetricSecureKey(Generate(KeySize.KeySize()));
		}

		return key;
	}
}

void SymmetricKeyGenerator::GetBytes(std::vector<byte> &Output)
{
	std::vector<byte> rnd = Generate(Output.size());
	Utility::MemUtils::Copy(rnd, 0, Output, 0, rnd.size());
}

std::vector<byte> SymmetricKeyGenerator::GetBytes(size_t Size)
{
	return Generate(Size);
}

//~~~Private Functions~~~//

std::vector<byte> SymmetricKeyGenerator::Generate(size_t KeySize)
{
	std::vector<byte> key(KeySize);

	if (KeySize == 0)
	{
		key.resize(0);
	}
	else
	{
		size_t keyLen = KeySize;
		size_t blkOff = 0;

		do
		{
			std::vector<byte> rnd = GenerateBlock();
			size_t alnLen = Utility::IntUtils::Min(keyLen, rnd.size());
			Utility::MemUtils::Copy(rnd, 0, key, blkOff, alnLen);
			keyLen -= alnLen;
			blkOff += alnLen;
		} 
		while (keyLen != 0);
	}

	return key;
}

std::vector<byte> SymmetricKeyGenerator::GenerateBlock()
{
	// seed size is 2x mac input block size less finalizer padding
	const size_t BLKLEN = Helper::DigestFromName::GetBlockSize(m_dgtType);
	size_t seedLen = (BLKLEN * 2) - Helper::DigestFromName::GetPaddingSize(m_dgtType);
	std::vector<byte> seed(seedLen);

	// generate the seed
	m_pvdEngine->GetBytes(seed);

	// get the hmac key from system entropy provider
	std::vector<byte> key(BLKLEN);
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

NAMESPACE_SYMMETRICKEYEND
