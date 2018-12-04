#include "DilithiumKeyPair.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

DilithiumKeyPair::DilithiumKeyPair(DilithiumPrivateKey* PrivateKey, DilithiumPublicKey* PublicKey)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(0)
{
}

DilithiumKeyPair::DilithiumKeyPair(DilithiumPrivateKey* PrivateKey, DilithiumPublicKey* PublicKey, std::vector<byte> &Tag)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(Tag)
{
}

DilithiumKeyPair::~DilithiumKeyPair()
{
	Destroy();
}

//~~~Accessors~~~//

IAsymmetricKey* DilithiumKeyPair::PrivateKey()
{
	return m_privateKey;
}

IAsymmetricKey* DilithiumKeyPair::PublicKey()
{
	return m_publicKey;
}

std::vector<byte> &DilithiumKeyPair::Tag()
{
	return m_Tag;
}

//~~~Private Functions~~~//

void DilithiumKeyPair::Destroy()
{
	if (m_Tag.size() != 0)
	{
		m_Tag.clear();
	}
}

NAMESPACE_ASYMMETRICKEYEND
