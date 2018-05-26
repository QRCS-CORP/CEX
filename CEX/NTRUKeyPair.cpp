#include "NTRUKeyPair.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

NTRUKeyPair::NTRUKeyPair(NTRUPrivateKey* PrivateKey, NTRUPublicKey* PublicKey)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(0)
{
}

NTRUKeyPair::NTRUKeyPair(NTRUPrivateKey* PrivateKey, NTRUPublicKey* PublicKey, std::vector<byte> &Tag)
	:
	m_privateKey(PrivateKey),
	m_publicKey(PublicKey),
	m_Tag(Tag)
{
}

NTRUKeyPair::~NTRUKeyPair()
{
	Destroy();
}

//~~~Accessors~~~//

IAsymmetricKey* NTRUKeyPair::PrivateKey()
{
	return m_privateKey;
}

IAsymmetricKey* NTRUKeyPair::PublicKey()
{
	return m_publicKey;
}

std::vector<byte> &NTRUKeyPair::Tag()
{
	return m_Tag;
}

//~~~Private Functions~~~//

void NTRUKeyPair::Destroy()
{
	if (m_Tag.size() != 0)
	{
		m_Tag.clear();
	}
}

NAMESPACE_ASYMMETRICKEYEND
