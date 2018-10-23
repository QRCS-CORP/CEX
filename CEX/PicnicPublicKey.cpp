#include "PicnicPublicKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

PicnicPublicKey::PicnicPublicKey(PicnicParams Parameters, std::vector<byte> &P)
	:
	m_isDestroyed(false),
	m_picnicParameters(Parameters),
	m_pCoeffs(P)
{
}

PicnicPublicKey::PicnicPublicKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_picnicParameters(PicnicParams::None),
	m_pCoeffs(0)
{
	m_picnicParameters = static_cast<PicnicParams>(KeyStream[0]);
	uint pLen = Utility::IntUtils::LeBytesTo32(KeyStream, 1);
	m_pCoeffs.resize(pLen);
	Utility::MemUtils::Copy(KeyStream, 5, m_pCoeffs, 0, pLen);
}

PicnicPublicKey::~PicnicPublicKey()
{
	Destroy();
}

//~~~Accessors~~~//

const AsymmetricEngines PicnicPublicKey::CipherType()
{
	return Enumeration::AsymmetricEngines::NTRU;
}

const AsymmetricKeyTypes PicnicPublicKey::KeyType()
{
	return AsymmetricKeyTypes::CipherPublicKey;
}

const PicnicParams PicnicPublicKey::Parameters()
{
	return m_picnicParameters;
}

const std::vector<byte> &PicnicPublicKey::P()
{
	return m_pCoeffs;
}

//~~~Public Functions~~~//

void PicnicPublicKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_picnicParameters = PicnicParams::None;

		if (m_pCoeffs.size() > 0)
		{
			Utility::IntUtils::ClearVector(m_pCoeffs);
		}
	}
}

std::vector<byte> PicnicPublicKey::ToBytes()
{
	uint pLen = static_cast<uint>(m_pCoeffs.size());
	std::vector<byte> p(pLen + 5);

	p[0] = static_cast<byte>(m_picnicParameters);
	Utility::IntUtils::Le32ToBytes(pLen, p, 1);
	Utility::MemUtils::Copy(m_pCoeffs, 0, p, 5, pLen);

	return p;
}

NAMESPACE_ASYMMETRICKEYEND
