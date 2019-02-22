#include "AsymmetricKeyPair.h"

NAMESPACE_ASYMMETRIC

//~~~Constructor~~~//

AsymmetricKeyPair::AsymmetricKeyPair(AsymmetricKey* PrivateKey, AsymmetricKey* PublicKey)
	:
	m_keyTag(0),
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey)
{
}

AsymmetricKeyPair::AsymmetricKeyPair(AsymmetricKey* PrivateKey, AsymmetricKey* PublicKey, std::vector<byte> &Tag)
	:
	m_keyTag(Tag),
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey)
{
}

AsymmetricKeyPair::~AsymmetricKeyPair()
{
	if (m_privateKey != nullptr)
	{
		m_privateKey.release();
	}
	if (m_publicKey != nullptr)
	{
		m_publicKey.release();
	}
	if (m_keyTag.size() != 0)
	{
		Utility::MemoryTools::Clear(m_keyTag, 0, m_keyTag.size());
		m_keyTag.clear();
	}
}

//~~~Accessors~~~//

AsymmetricKey* AsymmetricKeyPair::PrivateKey()
{
	return m_privateKey.get();
}

AsymmetricKey* AsymmetricKeyPair::PublicKey()
{
	return m_publicKey.get();
}

std::vector<byte> &AsymmetricKeyPair::Tag()
{
	return m_keyTag;
}

//~~~Private Functions~~~//

void AsymmetricKeyPair::Reset()
{
	if (m_privateKey != nullptr)
	{
		m_privateKey->Reset();
	}
	if (m_publicKey != nullptr)
	{
		m_publicKey->Reset();
	}
	if (m_keyTag.size() != 0)
	{
		Utility::MemoryTools::Clear(m_keyTag, 0, m_keyTag.size());
		m_keyTag.clear();
	}
}

NAMESPACE_ASYMMETRICEND
