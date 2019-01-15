#include "PaddingFromName.h"
#include "CryptoPaddingException.h"
#include "ESP.h"
#include "PKCS7.h"
#include "X923.h"
#include "ZeroOne.h"

NAMESPACE_HELPER

using Exception::CryptoPaddingException;
using Enumeration::ErrorCodes;

IPadding* PaddingFromName::GetInstance(PaddingModes PaddingType)
{
	using namespace Cipher::Block::Padding;

	IPadding* pptr = nullptr;

	try
	{
		switch (PaddingType)
		{
			case PaddingModes::ESP:
			{
				pptr = new ESP();
				break;
			}
			case PaddingModes::PKCS7:
			{
				pptr = new PKCS7();
				break;
			}
			case PaddingModes::X923:
			{
				pptr = new X923();
				break;
			}
			case PaddingModes::ZeroOne:
			{
				pptr = new ZeroOne();
				break;
			}
			default:
			{
				throw CryptoException(std::string("PaddingFromName"), std::string("GetInstance"), std::string("The padding mode type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoPaddingException &ex)
	{
		throw CryptoException(std::string("PaddingFromName"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(std::string("PaddingFromName"), std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return pptr;
}

NAMESPACE_HELPEREND
