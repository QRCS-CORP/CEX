#include "KdfFromName.h"
#include "CryptoKdfException.h"
#include "Digests.h"
#include "HKDF.h"
#include "KDF2.h"
#include "PBKDF2.h"
#include "SCBKDF.h"
#include "SHA2Digests.h"
#include "SHAKE.h"

NAMESPACE_HELPER

using Exception::CryptoKdfException;
using Enumeration::ErrorCodes;
using Enumeration::SHA2Digests;
using Enumeration::ShakeModes;

const std::string KdfFromName::CLASS_NAME("KdfFromName");

IKdf* KdfFromName::GetInstance(Kdfs KdfType)
{
	using namespace Kdf;

	IKdf* kptr;

	kptr = nullptr;

	try
	{
		switch (KdfType)
		{
			case Kdfs::HKDF256:
			{
				kptr = new HKDF(SHA2Digests::SHA2256);
				break;
			}
			case Kdfs::HKDF512:
			{
				kptr = new HKDF(SHA2Digests::SHA2512);
				break;
			}
			case Kdfs::KDF2256:
			{
				kptr = new KDF2(SHA2Digests::SHA2256);
				break;
			}
			case Kdfs::KDF2512:
			{
				kptr = new KDF2(SHA2Digests::SHA2512);
				break;
			}
			case Kdfs::PBKDF2256:
			{
				kptr = new PBKDF2(SHA2Digests::SHA2256);
				break;
			}
			case Kdfs::PBKDF2512:
			{
				kptr = new PBKDF2(SHA2Digests::SHA2512);
				break;
			}
			case Kdfs::SCBKDF128:
			{
				kptr = new SCBKDF(ShakeModes::SHAKE128);
				break;
			}
			case Kdfs::SCBKDF256:
			{
				kptr = new SCBKDF(ShakeModes::SHAKE256);
				break;
			}
			case Kdfs::SCBKDF512:
			{
				kptr = new SCBKDF(ShakeModes::SHAKE512);
				break;
			}
			case Kdfs::SHAKE128:
			{
				kptr = new SHAKE(ShakeModes::SHAKE128);
				break;
			}
			case Kdfs::SHAKE256:
			{
				kptr = new SHAKE(ShakeModes::SHAKE256);
				break;
			}
			case Kdfs::SHAKE512:
			{
				kptr = new SHAKE(ShakeModes::SHAKE512);
				break;
			}
			default:
			{
				// invaild parameter
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The kdf type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoKdfException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return kptr;
}

IKdf* KdfFromName::GetInstance(BlockCipherExtensions ExtensionType)
{
	using namespace Kdf;

	IKdf* kptr;

	kptr = nullptr;

	try
	{
		switch (ExtensionType)
		{
		case BlockCipherExtensions::HKDF256:
		{
			kptr = new HKDF(SHA2Digests::SHA2256);
			break;
		}
		case BlockCipherExtensions::HKDF512:
		{
			kptr = new HKDF(SHA2Digests::SHA2512);
			break;
		}
		case BlockCipherExtensions::SHAKE256:
		{
			kptr = new SHAKE(ShakeModes::SHAKE256);
			break;
		}
		case BlockCipherExtensions::SHAKE512:
		{
			kptr = new SHAKE(ShakeModes::SHAKE512);
			break;
		}
		default:
		{
			throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The kdf type is not supported!"), ErrorCodes::InvalidParam);
		}
		}
	}
	catch (CryptoKdfException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return kptr;
}

IKdf* KdfFromName::GetInstance(KdfDigests DigestType)
{
	using namespace Kdf;

	IKdf* kptr;

	kptr = nullptr;

	try
	{
		switch (DigestType)
		{
		case KdfDigests::SHA2256:
			{
				kptr = new HKDF(SHA2Digests::SHA2256);
				break;
			}
		case KdfDigests::SHA2512:
			{
				kptr = new HKDF(SHA2Digests::SHA2512);
				break;
			}
			case KdfDigests::SHAKE256:
			{
				kptr = new SHAKE(ShakeModes::SHAKE256);
				break;
			}
			case KdfDigests::SHAKE512:
			{
				kptr = new SHAKE(ShakeModes::SHAKE512);
				break;
			}
			default:
			{
				// invaild parameter
				throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string("The kdf type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoKdfException &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(CLASS_NAME, std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return kptr;
}

NAMESPACE_HELPEREND
