#include "MLWEPrivateKey.h"
#include "IntUtils.h"

NAMESPACE_ASYMMETRICKEY

//~~~Constructor~~~//

MLWEPrivateKey::MLWEPrivateKey(MLWEParameters Parameters, std::vector<byte> &R)
	:
	m_isDestroyed(false),
	m_mlweParameters(Parameters),
	m_rCoeffs(R)
{
}

MLWEPrivateKey::MLWEPrivateKey(const std::vector<byte> &KeyStream)
	:
	m_isDestroyed(false),
	m_mlweParameters(MLWEParameters::None),
	m_rCoeffs(0)
{
	m_mlweParameters = static_cast<MLWEParameters>(KeyStream[0]);
	uint rLen = Utility::IntUtils::LeBytesTo32(KeyStream, 1);
	m_rCoeffs.resize(rLen);

	for (size_t i = 0; i < rLen; ++i)
	{
		m_rCoeffs[i] = Utility::IntUtils::LeBytesTo16(KeyStream, 5 + (i * sizeof(ushort)));
	}
}

MLWEPrivateKey::~MLWEPrivateKey()
{
	Destroy();
}

//~~~Accessors~~~//

const AsymmetricEngines MLWEPrivateKey::CipherType()
{
	return AsymmetricEngines::ModuleLWE;
}

const AsymmetricKeyTypes MLWEPrivateKey::KeyType()
{
	return AsymmetricKeyTypes::CipherPrivateKey;
}

const MLWEParameters MLWEPrivateKey::Parameters()
{
	return m_mlweParameters;
}

const std::vector<byte> &MLWEPrivateKey::R()
{
	return m_rCoeffs;
}

//~~~Public Functions~~~//

void MLWEPrivateKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_mlweParameters = MLWEParameters::None;

		if (m_rCoeffs.size() > 0)
		{
			Utility::IntUtils::ClearVector(m_rCoeffs);
		}
	}
}

std::vector<byte> MLWEPrivateKey::ToBytes()
{
	uint rLen = static_cast<uint>(m_rCoeffs.size());
	std::vector<byte> r((rLen * sizeof(ushort)) + 5);
	r[0] = static_cast<byte>(m_mlweParameters);
	Utility::IntUtils::Le32ToBytes(rLen, r, 1);

	for (size_t i = 0; i < rLen; ++i)
	{
		Utility::IntUtils::Le16ToBytes(m_rCoeffs[i], r, 5 + (i * sizeof(ushort)));
	}

	return r;
}

NAMESPACE_ASYMMETRICKEYEND
