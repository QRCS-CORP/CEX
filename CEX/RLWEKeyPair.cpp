#include "RLWEKeyPair.h"

NAMESPACE_KEYASYMMETRIC

//~~~Constructor~~~//

RLWEKeyPair::RLWEKeyPair(RLWEPrivateKey* PrivateKey, RLWEPublicKey* PublicKey)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(0)
{
}

RLWEKeyPair::RLWEKeyPair(RLWEPrivateKey* PrivateKey, RLWEPublicKey* PublicKey, std::vector<byte> &Tag)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(Tag)
{
}

RLWEKeyPair::~RLWEKeyPair()
{
	Destroy();
}

//~~~Properties~~~//

IAsymmetricKey* RLWEKeyPair::PrivateKey()
{
	return m_privateKey;
}

IAsymmetricKey* RLWEKeyPair::PublicKey()
{
	return m_publicKey;
}

const std::vector<byte> &RLWEKeyPair::Tag()
{
	return m_Tag;
}

//~~~Private Functions~~~//

void RLWEKeyPair::Destroy()
{
	if (m_Tag.size() != 0)
		m_Tag.clear();
}

NAMESPACE_KEYASYMMETRICEND