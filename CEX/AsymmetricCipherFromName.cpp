#include "AsymmetricCipherFromName.h"
#include "ECDH.h"
#include "Kyber.h"
#include "McEliece.h"

NAMESPACE_HELPER

using Exception::CryptoAsymmetricException;
using Enumeration::ErrorCodes;

const std::string AsymmetricCipherFromName::CLASS_NAME("AsymmetricCipherFromName");

IAsymmetricCipher* AsymmetricCipherFromName::GetInstance(AsymmetricCiphers CipherType, AsymmetricParameters Parameters)
{
	using namespace Asymmetric::Encrypt;

	IAsymmetricCipher* mptr;

	try
	{
		switch (CipherType)
		{
			case AsymmetricCiphers::Kyber:
			{
				mptr = new MLWE::Kyber(static_cast<Enumeration::KyberParameters>(Parameters)); 
				break;
			}
			case AsymmetricCiphers::McEliece:
			{
				mptr = new MPKC::McEliece(static_cast<Enumeration::McElieceParameters>(Parameters)); 
				break;
			}
			default:
			{
				mptr = nullptr;
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The asymmetric cipher is not recognized!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoAsymmetricException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return mptr;
}

NAMESPACE_HELPEREND
