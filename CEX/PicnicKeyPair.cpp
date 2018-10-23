#include "PicnicKeyPair.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

PicnicKeyPair::PicnicKeyPair(PicnicPrivateKey* PrivateKey, PicnicPublicKey* PublicKey)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(0)
{
}

PicnicKeyPair::PicnicKeyPair(PicnicPrivateKey* PrivateKey, PicnicPublicKey* PublicKey, std::vector<byte> &Tag)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(Tag)
{
}

PicnicKeyPair::~PicnicKeyPair()
{
	Destroy();
}

//~~~Accessors~~~//

IAsymmetricKey* PicnicKeyPair::PrivateKey()
{
	return m_privateKey;
}

IAsymmetricKey* PicnicKeyPair::PublicKey()
{
	return m_publicKey;
}

std::vector<byte> &PicnicKeyPair::Tag()
{
	return m_Tag;
}

//~~~Private Functions~~~//

void PicnicKeyPair::Destroy()
{
	if (m_Tag.size() != 0)
	{
		m_Tag.clear();
	}
}

NAMESPACE_ASYMMETRICKEYEND
