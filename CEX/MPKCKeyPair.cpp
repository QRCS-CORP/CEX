#include "MPKCKeyPair.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

MPKCKeyPair::MPKCKeyPair(MPKCPrivateKey* PrivateKey, MPKCPublicKey* PublicKey)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(0)
{
}

MPKCKeyPair::MPKCKeyPair(MPKCPrivateKey* PrivateKey, MPKCPublicKey* PublicKey, std::vector<byte> &Tag)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(Tag)
{
}

MPKCKeyPair::~MPKCKeyPair()
{
	Destroy();
}

//~~~Accessors~~~//

IAsymmetricKey* MPKCKeyPair::PrivateKey()
{
	return m_privateKey;
}

IAsymmetricKey* MPKCKeyPair::PublicKey()
{
	return m_publicKey;
}

std::vector<byte> &MPKCKeyPair::Tag()
{
	return m_Tag;
}

//~~~Private Functions~~~//

void MPKCKeyPair::Destroy()
{
	if (m_Tag.size() != 0)
	{
		m_Tag.clear();
	}
}

NAMESPACE_ASYMMETRICKEYEND
