#include "AsymmetricSecureKey.h"
#include "ArrayTools.h"
#include "AsymmetricKey.h"
#include "CryptoAuthenticationFailure.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "SHAKE.h"
#include "StreamCipherFromName.h"
#include "SymmetricKey.h"
#include "SystemTools.h"

NAMESPACE_ASYMMETRIC

using Tools::ArrayTools;

using Exception::CryptoAuthenticationFailure;
using Enumeration::ErrorCodes;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Kdf::SHAKE;
using Enumeration::ShakeModes;
using Helper::StreamCipherFromName;
using Cipher::SymmetricKey;
using Cipher::SymmetricKeySize;
using Tools::SystemTools;

const std::string AsymmetricSecureKey::CLASS_NAME = "AsymmetricSecureKey";

//~~~State Container~~~//

class AsymmetricSecureKey::AsymmetricSecureKeyState
{
public:

	SecureVector<byte> Polynomial;
	SecureVector<byte> Salt;
	AsymmetricPrimitives Primitive;
	AsymmetricKeyTypes KeyClass;
	AsymmetricParameters Parameters;
	SecurityPolicy Policy;

	AsymmetricSecureKeyState()
		:
		Polynomial(0),
		Salt(0),
		KeyClass(AsymmetricKeyTypes::None),
		Parameters(AsymmetricParameters::None),
		Policy(SecurityPolicy::None),
		Primitive(AsymmetricPrimitives::None)
	{
	}

	AsymmetricSecureKeyState(const std::vector<byte> &Coefficients, AsymmetricPrimitives PrimitiveType, AsymmetricKeyTypes KeyClass, AsymmetricParameters ParameterType, const std::vector<byte> &KeySalt, SecurityPolicy PolicyType)
		:
		Polynomial(SecureLock(Coefficients)),
		Salt(SecureLock(KeySalt)),
		KeyClass(KeyClass),
		Primitive(PrimitiveType),
		Parameters(ParameterType),
		Policy(PolicyType)
	{
	}

	AsymmetricSecureKeyState(const SecureVector<byte> &Coefficients, AsymmetricPrimitives PrimitiveType, AsymmetricKeyTypes KeyClass, AsymmetricParameters ParameterType, const SecureVector<byte> &KeySalt, SecurityPolicy PolicyType)
		:
		Polynomial(Coefficients),
		Salt(KeySalt),
		KeyClass(KeyClass),
		Primitive(PrimitiveType),
		Parameters(ParameterType),
		Policy(PolicyType)
	{
	}

	~AsymmetricSecureKeyState()
	{
		Reset();
	}

	void Reset()
	{
		SecureClear(Polynomial);
		SecureClear(Salt);
		KeyClass = AsymmetricKeyTypes::None;
		Parameters = AsymmetricParameters::None;
		Policy = SecurityPolicy::None;
		Primitive = AsymmetricPrimitives::None;
	}
};

//~~~Constructors~~~//

AsymmetricSecureKey::AsymmetricSecureKey(const std::vector<byte> &Polynomial, const std::vector<byte> &KeySalt, AsymmetricPrimitives PrimitiveType, AsymmetricKeyTypes KeyClass, AsymmetricParameters Parameters, SecurityPolicy PolicyType)
	:
	m_secureState(Polynomial.size() != 0 && KeyClass != AsymmetricKeyTypes::None && PrimitiveType != AsymmetricPrimitives::None && Parameters != AsymmetricParameters::None && PolicyType != SecurityPolicy::None ?
		new AsymmetricSecureKeyState(Polynomial, PrimitiveType, KeyClass, Parameters, KeySalt, PolicyType) :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The parameters are invalid!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

AsymmetricSecureKey::AsymmetricSecureKey(const SecureVector<byte> &Polynomial, const SecureVector<byte> &KeySalt, AsymmetricPrimitives PrimitiveType, AsymmetricKeyTypes KeyClass, AsymmetricParameters Parameters, SecurityPolicy PolicyType)
	:
	m_secureState(Polynomial.size() != 0 && KeyClass != AsymmetricKeyTypes::None && PrimitiveType != AsymmetricPrimitives::None && Parameters != AsymmetricParameters::None && PolicyType != SecurityPolicy::None ?
		new AsymmetricSecureKeyState(Polynomial, PrimitiveType, KeyClass, Parameters, KeySalt, PolicyType) :
		throw CryptoAsymmetricException(CLASS_NAME, std::string("Constructor"), std::string("The parameters are invalid!"), ErrorCodes::InvalidParam))
{
	Encipher(m_secureState);
}

AsymmetricSecureKey::~AsymmetricSecureKey()
{
	Reset();
}

//~~~Accessors~~~//

const AsymmetricPrimitives AsymmetricSecureKey::PrimitiveType()
{
	return m_secureState->Primitive;
}

const AsymmetricKeyTypes AsymmetricSecureKey::KeyClass()
{
	return m_secureState->KeyClass;
}

const AsymmetricParameters AsymmetricSecureKey::Parameters()
{
	return m_secureState->Parameters;
}

const std::vector<byte> AsymmetricSecureKey::Polynomial()
{
	SecureVector<byte> tmps(m_secureState->Polynomial.size());

	// if the state policy has been set to authenticated mode, this will throw on authentication failure
	try
	{
		Extract(m_secureState, tmps, m_secureState->Polynomial.size());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("Polynomial"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}

	return SecureUnlockClear(tmps);
}

const void AsymmetricSecureKey::SecurePolynomial(SecureVector<byte> &Output)
{
	if (Output.size() < m_secureState->Polynomial.size())
	{
		throw CryptoAsymmetricException(CLASS_NAME, std::string("SecurePolynomial"), std::string("The output vector is too small!"), ErrorCodes::InvalidSize);
	}

	// if the state policy has been set to authenticated mode, this will throw on authentication failure
	try
	{
		Extract(m_secureState, Output, m_secureState->Polynomial.size());
	}
	catch (CryptoAuthenticationFailure &ex)
	{
		throw CryptoAuthenticationFailure(CLASS_NAME, std::string("SecurePolynomial"), ex.Message(), ErrorCodes::AuthenticationFailure);
	}
}

//~~~Public Functions~~~//

void AsymmetricSecureKey::Reset()
{
	m_secureState->Reset();
}

//~~~Static Functions~~~//

AsymmetricKey* AsymmetricSecureKey::DeSerialize(SecureVector<byte> &KeyStream)
{
	AsymmetricKey* tmpk = AsymmetricKey::DeSerialize(KeyStream);

	return tmpk;
}

SecureVector<byte> AsymmetricSecureKey::Serialize(AsymmetricSecureKey &KeyParams)
{
	SecureVector<byte> tmpr(0);

	ArrayTools::AppendValue(static_cast<byte>(KeyParams.KeyClass()), tmpr);
	ArrayTools::AppendValue(static_cast<byte>(KeyParams.Parameters()), tmpr);
	ArrayTools::AppendValue(static_cast<byte>(KeyParams.PrimitiveType()), tmpr);
	ArrayTools::AppendVector(KeyParams.Polynomial(), tmpr);

	return tmpr;
}

//~~~Private Functions~~~//

void AsymmetricSecureKey::Encipher(std::unique_ptr<AsymmetricSecureKeyState> &State)
{
	IStreamCipher* cpr = GetStreamCipher(State->Policy);
	SymmetricKeySize ksc = cpr->LegalKeySizes()[0];
	SecureVector<byte> seed(ksc.KeySize() + ksc.IVSize());
	std::vector<byte> tmpt(0);
	std::vector<byte> tmpk(ksc.KeySize());
	std::vector<byte> tmpn(ksc.IVSize());
	std::vector<byte> cpt(State->Polynomial.size());

	// transfer from the secure-vector to a working state
	tmpt = SecureUnlockClear(State->Polynomial);

	// resize the cipher-text to accommodate the authentication tag
	if (cpr->IsAuthenticator())
	{
		cpt.resize(cpt.size() + cpr->TagSize());
	}

	// assemble the cipher key
	GetSystemKey(State->Policy, State->Salt, seed);
	MemoryTools::Copy(seed, 0, tmpk, 0, tmpk.size());
	MemoryTools::Copy(seed, tmpk.size(), tmpn, 0, tmpn.size());
	SymmetricKey kpc(tmpk, tmpn);
	// transform the temp state
	cpr->Initialize(true, kpc);
	cpr->Transform(tmpt, 0, cpt, 0, tmpt.size());
	// copy the encrypted cipher-text to secure state and erase buffer
	State->Polynomial = SecureLockClear(cpt);
}

void AsymmetricSecureKey::Extract(std::unique_ptr<AsymmetricSecureKeyState> &State, SecureVector<byte> &Output, size_t Length)
{
	IStreamCipher* cpr = GetStreamCipher(State->Policy);
	const size_t CPTSZE = cpr->IsAuthenticator() ? State->Polynomial.size() - cpr->TagSize() : State->Polynomial.size();
	SymmetricKeySize ksc = cpr->LegalKeySizes()[0];
	SecureVector<byte> seed(ksc.KeySize() + ksc.IVSize());
	std::vector<byte> tmpt(State->Polynomial.size());
	std::vector<byte> tmpk(ksc.KeySize());
	std::vector<byte> tmpn(ksc.IVSize());

	// assemble the cipher key
	GetSystemKey(State->Policy, State->Salt, seed);
	MemoryTools::Copy(seed, 0, tmpk, 0, tmpk.size());
	MemoryTools::Copy(seed, tmpk.size(), tmpn, 0, tmpn.size());
	SymmetricKey kpc(tmpk, tmpn);
	cpr->Initialize(false, kpc);
	// copy from secure-vector to cipher-text buffer
	std::vector<byte> cpt = SecureUnlock(State->Polynomial);
	// decrypt to temp state
	cpr->Transform(cpt, 0, tmpt, 0, CPTSZE);
	// erase the temp cipher-text
	MemoryTools::Clear(cpt, 0, cpt.size());
	// copy the decrypted key to output
	MemoryTools::Copy(tmpt, 0, Output, 0, Length);
	// erase the temp state
	MemoryTools::Clear(tmpt, 0, tmpt.size());
}

IStreamCipher* AsymmetricSecureKey::GetStreamCipher(SecurityPolicy Policy)
{
	IStreamCipher* cpr;

	switch (Policy)
	{
		case SecurityPolicy::SPL256:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSX256);
			break;
		}
		case SecurityPolicy::SPL256AE:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSXR120K1024);
			break;
		}
		case SecurityPolicy::SPL512:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSX512);
			break;
		}
		case SecurityPolicy::SPL512AE:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSXR96K512);
			break;
		}
		case SecurityPolicy::SPL1024:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSX1024);
			break;
		}
		case SecurityPolicy::SPL1024AE:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSXR120K1024);
			break;
		}
		default:
		{
			cpr = StreamCipherFromName::GetInstance(Enumeration::StreamCiphers::TSXR96K512);
			break;
		}
	}

	return cpr;
}

void AsymmetricSecureKey::GetSystemKey(SecurityPolicy Policy, const SecureVector<byte> &Salt, SecureVector<byte> &Output)
{
	std::vector<byte> cust(0);
	CpuDetect dtc;
	ShakeModes mode;

	ArrayTools::AppendString(SystemTools::ComputerName(), cust);
	ArrayTools::AppendString(SystemTools::OsName(), cust);
	ArrayTools::AppendString(SystemTools::UserId(), cust);
	ArrayTools::AppendString(SystemTools::UserName(), cust);
	ArrayTools::AppendValue(SystemTools::ProcessId(), cust);
	ArrayTools::AppendValue(dtc.BusRefFrequency(), cust);
	ArrayTools::AppendValue(dtc.FrequencyBase(), cust);
	ArrayTools::AppendValue(dtc.FrequencyMax(), cust);
	ArrayTools::AppendValue(dtc.L1CacheLineSize(), cust);
	ArrayTools::AppendValue(dtc.L1CacheSize(), cust);
	ArrayTools::AppendValue(dtc.L2CacheSize(), cust);
	ArrayTools::AppendString(dtc.SerialNumber(), cust);
	ArrayTools::AppendValue(dtc.Vendor(), cust);

	switch (Policy)
	{
		case SecurityPolicy::SPL256:
		case SecurityPolicy::SPL256AE:
		{
			mode = ShakeModes::SHAKE256;
			break;
		}
		case SecurityPolicy::SPL512:
		case SecurityPolicy::SPL512AE:
		{
			mode = ShakeModes::SHAKE512;
			break;
		}
		default:
		{
			mode = ShakeModes::SHAKE1024;
			break;
		}
	}

	SHAKE gen(mode);
	gen.Initialize(cust, SecureUnlock(Salt));
	gen.Generate(Output, 0, Output.size());
}

NAMESPACE_ASYMMETRICEND
