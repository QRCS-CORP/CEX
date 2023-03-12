#include "AsymmetricKeyPair.h"

NAMESPACE_ASYMMETRIC

using Tools::MemoryTools;

//~~~Constructor~~~//

AsymmetricKeyPair::AsymmetricKeyPair(AsymmetricKey* PrivateKey, AsymmetricKey* PublicKey)
	:
	m_keyTag(0),
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey)
{
}

AsymmetricKeyPair::AsymmetricKeyPair(AsymmetricKey* PrivateKey, AsymmetricKey* PublicKey, std::vector<uint8_t> &Tag)
	:
	m_keyTag(Tag),
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey)
{
}

AsymmetricKeyPair::~AsymmetricKeyPair()
{
	Reset();
}

//~~~Accessors~~~//

AsymmetricKey* AsymmetricKeyPair::PrivateKey()
{
	return m_privateKey;
}

AsymmetricKey* AsymmetricKeyPair::PublicKey()
{
	return m_publicKey;
}

std::vector<uint8_t> &AsymmetricKeyPair::Tag()
{
	return m_keyTag;
}

//~~~Private Functions~~~//

void AsymmetricKeyPair::Reset()
{
	if (m_privateKey != nullptr)
	{
		delete m_privateKey;
		m_privateKey = nullptr;
	}

	if (m_publicKey != nullptr)
	{
		delete m_publicKey;
		m_publicKey = nullptr;
	}

	if (m_keyTag.size() != 0)
	{
		MemoryTools::Clear(m_keyTag, 0, m_keyTag.size());
		m_keyTag.clear();
	}
}

NAMESPACE_ASYMMETRICEND
