#include "MLWEKeyPair.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

MLWEKeyPair::MLWEKeyPair(MLWEPrivateKey* PrivateKey, MLWEPublicKey* PublicKey)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(0)
{
}

MLWEKeyPair::MLWEKeyPair(MLWEPrivateKey* PrivateKey, MLWEPublicKey* PublicKey, std::vector<byte> &Tag)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(Tag)
{
}

MLWEKeyPair::~MLWEKeyPair()
{
	Destroy();
}

//~~~Accessors~~~//

IAsymmetricKey* MLWEKeyPair::PrivateKey()
{
	return m_privateKey;
}

IAsymmetricKey* MLWEKeyPair::PublicKey()
{
	return m_publicKey;
}

std::vector<byte> &MLWEKeyPair::Tag()
{
	return m_Tag;
}

//~~~Private Functions~~~//

void MLWEKeyPair::Destroy()
{
	if (m_Tag.size() != 0)
	{
		m_Tag.clear();
	}
}

NAMESPACE_ASYMMETRICKEYEND
