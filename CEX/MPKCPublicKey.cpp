#include "MPKCPublicKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

MPKCPublicKey::MPKCPublicKey(MPKCParams Params, const std::vector<byte> &P)
	:
	m_mpkcParameters(Params),
	m_isDestroyed(false),
	m_pubMat(P)
{
}

MPKCPublicKey::MPKCPublicKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_mpkcParameters(MPKCParams::None),
	m_pubMat(0)
{
	m_mpkcParameters = static_cast<MPKCParams>(KeyStream[0]);
	uint pLen = Utility::IntUtils::LeBytesTo32(KeyStream, 1);
	m_pubMat.resize(pLen);
	Utility::MemUtils::Copy(KeyStream, 5, m_pubMat, 0, pLen);
}

MPKCPublicKey::~MPKCPublicKey()
{
	Destroy();
}

//~~~Accessors~~~//

const AsymmetricEngines MPKCPublicKey::CipherType()
{
	return Enumeration::AsymmetricEngines::McEliece;
}

const MPKCParams MPKCPublicKey::Parameters()
{
	return m_mpkcParameters;
}

const std::vector<byte> &MPKCPublicKey::P()
{
	return m_pubMat;
}

//~~~Public Functions~~~//

void MPKCPublicKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_mpkcParameters = MPKCParams::None;

		if (m_pubMat.size() > 0)
		{
			Utility::IntUtils::ClearVector(m_pubMat);
		}
	}
}

std::vector<byte> MPKCPublicKey::ToBytes()
{
	uint pLen = static_cast<uint>(m_pubMat.size());
	std::vector<byte> p(pLen + 5);
	p[0] = static_cast<byte>(m_mpkcParameters);
	Utility::IntUtils::Le32ToBytes(pLen, p, 1);
	Utility::MemUtils::Copy(m_pubMat, 0, p, 5, pLen);

	return p;
}

NAMESPACE_ASYMMETRICKEYEND
