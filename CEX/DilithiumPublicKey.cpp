#include "DilithiumPublicKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

DilithiumPublicKey::DilithiumPublicKey(DilithiumParameters Parameters, std::vector<byte> &P)
	:
	m_isDestroyed(false),
	m_dilithiumParameters(Parameters),
	m_pCoeffs(P)
{
}

DilithiumPublicKey::DilithiumPublicKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_dilithiumParameters(DilithiumParameters::None),
	m_pCoeffs(0)
{
	m_dilithiumParameters = static_cast<DilithiumParameters>(KeyStream[0]);
	uint pLen = Utility::IntUtils::LeBytesTo32(KeyStream, 1);
	m_pCoeffs.resize(pLen);
	Utility::MemUtils::Copy(KeyStream, 5, m_pCoeffs, 0, pLen);
}

DilithiumPublicKey::~DilithiumPublicKey()
{
	Destroy();
}

//~~~Accessors~~~//

const AsymmetricEngines DilithiumPublicKey::CipherType()
{
	return Enumeration::AsymmetricEngines::Dilithium;
}

const AsymmetricKeyTypes DilithiumPublicKey::KeyType()
{
	return AsymmetricKeyTypes::CipherPublicKey;
}

const DilithiumParameters DilithiumPublicKey::Parameters()
{
	return m_dilithiumParameters;
}

const std::vector<byte> &DilithiumPublicKey::P()
{
	return m_pCoeffs;
}

//~~~Public Functions~~~//

void DilithiumPublicKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_dilithiumParameters = DilithiumParameters::None;

		if (m_pCoeffs.size() > 0)
		{
			Utility::IntUtils::ClearVector(m_pCoeffs);
		}
	}
}

std::vector<byte> DilithiumPublicKey::ToBytes()
{
	uint pLen = static_cast<uint>(m_pCoeffs.size());
	std::vector<byte> p(pLen + 5);

	p[0] = static_cast<byte>(m_dilithiumParameters);
	Utility::IntUtils::Le32ToBytes(pLen, p, 1);
	Utility::MemUtils::Copy(m_pCoeffs, 0, p, 5, pLen);

	return p;
}

NAMESPACE_ASYMMETRICKEYEND
