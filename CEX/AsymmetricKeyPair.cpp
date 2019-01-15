#include "AsymmetricKeyPair.h"

NAMESPACE_ASYMMETRIC

//~~~Constructor~~~//

AsymmetricKeyPair::AsymmetricKeyPair(AsymmetricKey* PrivateKey, AsymmetricKey* PublicKey)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(0)
{
}

AsymmetricKeyPair::AsymmetricKeyPair(AsymmetricKey* PrivateKey, AsymmetricKey* PublicKey, std::vector<byte> &Tag)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(Tag)
{
}

AsymmetricKeyPair::~AsymmetricKeyPair()
{
	Destroy();
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

std::vector<byte> &AsymmetricKeyPair::Tag()
{
	return m_Tag;
}

//~~~Private Functions~~~//

void AsymmetricKeyPair::Destroy()
{
	if (m_privateKey != nullptr)
	{
		m_privateKey->Destroy();
	}
	if (m_publicKey != nullptr)
	{
		m_publicKey->Destroy();
	}
	if (m_Tag.size() != 0)
	{
		m_Tag.clear();
	}
}

NAMESPACE_ASYMMETRICEND
