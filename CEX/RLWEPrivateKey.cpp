#include "RLWEPrivateKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

RLWEPrivateKey::RLWEPrivateKey(RLWEParameters Parameters, std::vector<byte> &R)
	:
	m_isDestroyed(false),
	m_rlweParameters(Parameters),
	m_rCoeffs(R)
{
}

RLWEPrivateKey::RLWEPrivateKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_rlweParameters(RLWEParameters::None),
	m_rCoeffs(0)
{
	m_rlweParameters = static_cast<RLWEParameters>(KeyStream[0]);
	uint rLen = Utility::IntUtils::LeBytesTo32(KeyStream, 1);
	m_rCoeffs.resize(rLen);
	Utility::MemUtils::Copy(KeyStream, 5, m_rCoeffs, 0, rLen);
}

RLWEPrivateKey::~RLWEPrivateKey()
{
	Destroy();
}

//~~~Accessors~~~//

const AsymmetricEngines RLWEPrivateKey::CipherType()
{
	return AsymmetricEngines::RingLWE;
}

const AsymmetricKeyTypes RLWEPrivateKey::KeyType()
{
	return AsymmetricKeyTypes::CipherPrivateKey;
}

const RLWEParameters RLWEPrivateKey::Parameters()
{
	return m_rlweParameters;
}

const std::vector<byte> &RLWEPrivateKey::R()
{
	return m_rCoeffs;
}

//~~~Public Functions~~~//

void RLWEPrivateKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_rlweParameters = RLWEParameters::None;

		if (m_rCoeffs.size() > 0)
		{
			Utility::IntUtils::ClearVector(m_rCoeffs);
		}
	}
}

std::vector<byte> RLWEPrivateKey::ToBytes()
{
	uint rLen = static_cast<uint>(m_rCoeffs.size());
	std::vector<byte> r(rLen + 5);
	r[0] = static_cast<byte>(m_rlweParameters);
	Utility::IntUtils::Le32ToBytes(rLen, r, 1);
	Utility::MemUtils::Copy(m_rCoeffs, 0, r, 5, rLen);

	return r;
}

NAMESPACE_ASYMMETRICKEYEND
