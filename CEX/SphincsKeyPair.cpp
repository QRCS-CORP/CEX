#include "SphincsKeyPair.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

SphincsKeyPair::SphincsKeyPair(SphincsPrivateKey* PrivateKey, SphincsPublicKey* PublicKey)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(0)
{
}

SphincsKeyPair::SphincsKeyPair(SphincsPrivateKey* PrivateKey, SphincsPublicKey* PublicKey, std::vector<byte> &Tag)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(Tag)
{
}

SphincsKeyPair::~SphincsKeyPair()
{
	Destroy();
}

//~~~Accessors~~~//

IAsymmetricKey* SphincsKeyPair::PrivateKey()
{
	return m_privateKey;
}

IAsymmetricKey* SphincsKeyPair::PublicKey()
{
	return m_publicKey;
}

std::vector<byte> &SphincsKeyPair::Tag()
{
	return m_Tag;
}

//~~~Private Functions~~~//

void SphincsKeyPair::Destroy()
{
	if (m_Tag.size() != 0)
	{
		m_Tag.clear();
	}
}

NAMESPACE_ASYMMETRICKEYEND
