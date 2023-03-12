#include "AsymmetricKey.h"
#include "ArrayTools.h"
#include "IntegerTools.h"

NAMESPACE_ASYMMETRIC

using Enumeration::ErrorCodes;
using Tools::ArrayTools;
using Tools::IntegerTools;
using Tools::MemoryTools;

const std::string AsymmetricKey::CLASS_NAME = "AsymmetricKey";

//~~~State Container~~~//

class AsymmetricKey::AsymmetricKeyState
{
public:

	SecureVector<uint8_t> Polynomial;
	AsymmetricKeyTypes KeyClass;
	AsymmetricPrimitives Primitive;
	AsymmetricParameters Parameters;

	AsymmetricKeyState(const std::vector<uint8_t> &Poly, AsymmetricPrimitives PrimitiveType, AsymmetricKeyTypes AsymmetricKeyType, AsymmetricParameters ParameterType)
		:
		Polynomial(SecureLock(Poly)),
		Primitive(PrimitiveType),
		KeyClass(AsymmetricKeyType),
		Parameters(ParameterType)
	{
	}

	AsymmetricKeyState(const SecureVector<uint8_t> &Poly, AsymmetricPrimitives AsymmetricType, AsymmetricKeyTypes AsymmetricKeyType, AsymmetricParameters ParameterType)
		:
		Polynomial(Poly),
		Primitive(AsymmetricType),
		KeyClass(AsymmetricKeyType),
		Parameters(ParameterType)
	{
	}

	AsymmetricKeyState(const std::vector<uint8_t> &KeyStream)
		:
		KeyClass(static_cast<AsymmetricKeyTypes>(KeyStream[0])),
		Parameters(static_cast<AsymmetricParameters>(KeyStream[1])),
		Primitive(static_cast<AsymmetricPrimitives>(KeyStream[2])),
		Polynomial(KeyStream.begin() + 3, KeyStream.end())
	{
	}

	AsymmetricKeyState(const SecureVector<uint8_t> &KeyStream)
		:
		KeyClass(static_cast<AsymmetricKeyTypes>(KeyStream[0])),
		Parameters(static_cast<AsymmetricParameters>(KeyStream[1])),
		Primitive(static_cast<AsymmetricPrimitives>(KeyStream[2])),
		Polynomial(KeyStream.begin() + 3, KeyStream.end())
	{
	}

	~AsymmetricKeyState()
	{
		Reset();
	}

	void Reset()
	{
		SecureClear(Polynomial);
		Primitive = AsymmetricPrimitives::None;
		KeyClass = AsymmetricKeyTypes::None;
		Parameters = AsymmetricParameters::None;
	}
};

//~~~Constructors~~~//

AsymmetricKey::AsymmetricKey(const std::vector<uint8_t> &Polynomial, AsymmetricPrimitives PrimitiveType, AsymmetricKeyTypes CipherKeyType, AsymmetricParameters ParameterType)
	:
	m_keyState((Polynomial.size() != 0 && PrimitiveType != AsymmetricPrimitives::None && CipherKeyType != AsymmetricKeyTypes::None && ParameterType != AsymmetricParameters::None) ?
		new AsymmetricKeyState(Polynomial, PrimitiveType, CipherKeyType, ParameterType) :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The types can not be none and the polynomial array can not be zero length!"), Enumeration::ErrorCodes::InvalidParam))
{
}

AsymmetricKey::AsymmetricKey(const SecureVector<uint8_t> &Polynomial, AsymmetricPrimitives PrimitiveType, AsymmetricKeyTypes CipherKeyType, AsymmetricParameters ParameterType)
	:
	m_keyState((Polynomial.size() != 0 && PrimitiveType != AsymmetricPrimitives::None && CipherKeyType != AsymmetricKeyTypes::None && ParameterType != AsymmetricParameters::None) ?
		new AsymmetricKeyState(Polynomial, PrimitiveType, CipherKeyType, ParameterType) :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The types can not be none and the polynomial array can not be zero length!"), Enumeration::ErrorCodes::InvalidParam))
{
}

AsymmetricKey::~AsymmetricKey()
{
}

//~~~Accessors~~~//

const AsymmetricPrimitives AsymmetricKey::PrimitiveType()
{
	return m_keyState->Primitive;
}

const AsymmetricKeyTypes AsymmetricKey::KeyClass()
{
	return m_keyState->KeyClass;
}

const AsymmetricParameters AsymmetricKey::Parameters()
{
	return m_keyState->Parameters;
}

const std::vector<uint8_t> AsymmetricKey::Polynomial()
{
	std::vector<uint8_t> tmp = SecureUnlock(m_keyState->Polynomial);
	return tmp;
}

const SecureVector<uint8_t> &AsymmetricKey::SecurePolynomial()
{
	return m_keyState->Polynomial;
}

//~~~Public Functions~~~//

void AsymmetricKey::Reset()
{
	m_keyState->Reset();
}

//~~~Static Functions~~~//

AsymmetricKey* AsymmetricKey::DeSerialize(SecureVector<uint8_t> &KeyStream)
{
	AsymmetricKey* tmpk = new AsymmetricKey(SecureVector<uint8_t>(KeyStream.begin() + 3, KeyStream.end()), 
		static_cast<AsymmetricPrimitives>(KeyStream[2]),
		static_cast<AsymmetricKeyTypes>(KeyStream[0]),
		static_cast<AsymmetricParameters>(KeyStream[1]));

	return tmpk;
}

SecureVector<uint8_t> AsymmetricKey::Serialize(AsymmetricKey &KeyParams)
{
	SecureVector<uint8_t> tmpr(0);

	ArrayTools::AppendValue(static_cast<uint8_t>(KeyParams.KeyClass()), tmpr);
	ArrayTools::AppendValue(static_cast<uint8_t>(KeyParams.Parameters()), tmpr);
	ArrayTools::AppendValue(static_cast<uint8_t>(KeyParams.PrimitiveType()), tmpr);
	ArrayTools::AppendVector(KeyParams.Polynomial(), tmpr);

	return tmpr;
}

NAMESPACE_ASYMMETRICEND
