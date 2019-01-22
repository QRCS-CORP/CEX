#include "AsymmetricKey.h"
#include "IntegerTools.h"

NAMESPACE_ASYMMETRIC

using Enumeration::ErrorCodes;
using Utility::IntegerTools;
using Utility::MemoryTools;

const std::string AsymmetricKey::CLASS_NAME = "AsymmetricKey";

AsymmetricKey::AsymmetricKey(AsymmetricEngines CipherType, AsymmetricKeyTypes CipherKeyType, AsymmetricTransforms ParameterType, std::vector<byte> &P)
	:
	m_cipherEngine(CipherType != AsymmetricEngines::None ? CipherType :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The cipher engine type can not be None!"), Enumeration::ErrorCodes::InvalidParam)),
	m_cipherKey(CipherKeyType != AsymmetricKeyTypes::None ? CipherKeyType :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The cipher key type can not be None!"), Enumeration::ErrorCodes::InvalidParam)),
	m_cipherParams(ParameterType != AsymmetricTransforms::None ? ParameterType :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The cipher parameters type can not be None!"), Enumeration::ErrorCodes::InvalidParam)),
	m_isDestroyed(false),
	m_polyCoeffs(P.size() != 0 ? P :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The polynomial array can not be zero length!"), Enumeration::ErrorCodes::InvalidParam))
{
}

AsymmetricKey::AsymmetricKey(const std::vector<byte> &KeyStream)
	:
	m_cipherEngine(static_cast<AsymmetricEngines>(KeyStream[0])),
	m_cipherKey(static_cast<AsymmetricKeyTypes>(KeyStream[1])),
	m_cipherParams(static_cast<AsymmetricTransforms>(KeyStream[2])),
	m_isDestroyed(false),
	m_polyCoeffs(KeyStream.begin() + 7, KeyStream.begin() + 7 + IntegerTools::LeBytesTo32(KeyStream, 3))
{
}

AsymmetricKey::~AsymmetricKey()
{
	Destroy();
}

const AsymmetricEngines AsymmetricKey::CipherType()
{
	return m_cipherEngine;
}

const AsymmetricKeyTypes AsymmetricKey::KeyType()
{
	return m_cipherKey;
}

const AsymmetricTransforms AsymmetricKey::Parameters()
{
	return m_cipherParams;
}

const std::vector<byte> &AsymmetricKey::P()
{
	return m_polyCoeffs;
}

void AsymmetricKey::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_cipherEngine = AsymmetricEngines::None;
		m_cipherKey = AsymmetricKeyTypes::None;
		m_cipherParams = AsymmetricTransforms::None;

		if (m_polyCoeffs.size() > 0)
		{
			IntegerTools::Clear(m_polyCoeffs);
		}
	}
}

std::vector<byte> AsymmetricKey::ToBytes()
{
	const uint PLYLEN = static_cast<uint>(m_polyCoeffs.size());
	std::vector<byte> poly(PLYLEN + 7);

	poly[0] = static_cast<byte>(m_cipherEngine);
	poly[1] = static_cast<byte>(m_cipherKey);
	poly[2] = static_cast<byte>(m_cipherParams);
	IntegerTools::Le32ToBytes(PLYLEN, poly, 3);
	MemoryTools::Copy(m_polyCoeffs, 0, poly, 7, PLYLEN);

	return poly;
}

NAMESPACE_ASYMMETRICEND
