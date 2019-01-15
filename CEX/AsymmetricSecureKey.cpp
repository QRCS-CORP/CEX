#include "AsymmetricSecureKey.h"
#include "IntegerTools.h"

NAMESPACE_ASYMMETRIC

using Utility::IntegerTools;
using Utility::MemoryTools;

AsymmetricSecureKey::AsymmetricSecureKey(AsymmetricEngines CipherType, AsymmetricKeyTypes CipherKeyType, AsymmetricTransforms ParameterType, std::vector<byte> &P, ulong KeySalt)
	:
	m_cipherEngine(CipherType != AsymmetricEngines::None ? CipherType :
		throw CryptoAsymmetricException(std::string("AsymmetricSecureKey"), std::string("Constructor"), std::string("The cipher engine type can not be None!"), Enumeration::ErrorCodes::InvalidParam)),
	m_cipherKey(CipherKeyType != AsymmetricKeyTypes::None ? CipherKeyType :
		throw CryptoAsymmetricException(std::string("AsymmetricSecureKey"), std::string("Constructor"), std::string("The cipher key type can not be None!"), Enumeration::ErrorCodes::InvalidParam)),
	m_cipherParams(ParameterType != AsymmetricTransforms::None ? ParameterType :
		throw CryptoAsymmetricException(std::string("AsymmetricSecureKey"), std::string("Constructor"), std::string("The cipher parameters type can not be None!"), Enumeration::ErrorCodes::InvalidParam)),
	m_isDestroyed(false),
	m_polyCoeffs(P.size() != 0 ? P :
		throw CryptoAsymmetricException(std::string("AsymmetricSecureKey"), std::string("Constructor"), std::string("The polynomial array can not be zero length!"), Enumeration::ErrorCodes::InvalidParam))
{
	throw; // not completed yet!
}

AsymmetricSecureKey::AsymmetricSecureKey(const std::vector<byte> &KeyStream)
	:
	m_cipherEngine(static_cast<AsymmetricEngines>(KeyStream[0])),
	m_cipherKey(static_cast<AsymmetricKeyTypes>(KeyStream[1])),
	m_cipherParams(static_cast<AsymmetricTransforms>(KeyStream[2])),
	m_isDestroyed(false),
	m_polyCoeffs(KeyStream.begin() + 7, KeyStream.begin() + 7 + IntegerTools::LeBytesTo32(KeyStream, 3))
{
	throw; // not completed yet!
}

AsymmetricSecureKey::~AsymmetricSecureKey()
{
	Destroy();
}

const AsymmetricEngines AsymmetricSecureKey::CipherType()
{
	return m_cipherEngine;
}

const AsymmetricKeyTypes AsymmetricSecureKey::KeyType()
{
	return m_cipherKey;
}

const AsymmetricTransforms AsymmetricSecureKey::Parameters()
{
	return m_cipherParams;
}

const std::vector<byte> &AsymmetricSecureKey::P()
{
	return m_polyCoeffs;
}

void AsymmetricSecureKey::Destroy()
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

std::vector<byte> AsymmetricSecureKey::ToBytes()
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
