#include "AsymmetricSignerFromName.h"
#include "Dilithium.h"
#include "Rainbow.h"
#include "SphincsPlus.h"
#include "XMSS.h"

NAMESPACE_HELPER

using Exception::CryptoAsymmetricException;
using Enumeration::ErrorCodes;

const std::string AsymmetricSignerFromName::CLASS_NAME("AsymmetricSignerFromName");

IAsymmetricSigner* AsymmetricSignerFromName::GetInstance(AsymmetricSigners SignerType, AsymmetricParameters Parameters)
{
	using namespace Asymmetric::Sign;

	IAsymmetricSigner* mptr;

	try
	{
		switch (SignerType)
		{
			case AsymmetricSigners::Dilithium:
			{
				mptr = new DLTM::Dilithium(static_cast<Enumeration::DilithiumParameters>(Parameters)); 
				break;
			}
			case AsymmetricSigners::Rainbow:
			{
				mptr = new RNBW::Rainbow(static_cast<Enumeration::RainbowParameters>(Parameters)); 
				break;
			}
			case AsymmetricSigners::SphincsPlus:
			{
				mptr = new SPXP::SphincsPlus(static_cast<Enumeration::SphincsPlusParameters>(Parameters)); 
				break;
			}
			case AsymmetricSigners::XMSS:
			{
				mptr = new XMSS::XMSS(static_cast<Enumeration::XmssParameters>(Parameters)); 
				break;
			}
			default:
			{
				mptr = nullptr;
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The asymmetric signature scheme is not recognized!"), ErrorCodes::InvalidParam);
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
