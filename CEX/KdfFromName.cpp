#include "KdfFromName.h"
#include "CryptoKdfException.h"
#include "Digests.h"
#include "HKDF.h"
#include "KDF2.h"
#include "PBKDF2.h"
#include "SCRYPT.h"
#include "SHA2Digests.h"
#include "SHAKE.h"

NAMESPACE_HELPER

using Exception::CryptoKdfException;
using Enumeration::ErrorCodes;
using Enumeration::SHA2Digests;
using Enumeration::ShakeModes;

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
				kptr = new HKDF(SHA2Digests::SHA256);
				break;
			}
			case Kdfs::HKDF512:
			{
				kptr = new HKDF(SHA2Digests::SHA512);
				break;
			}
			case Kdfs::KDF2256:
			{
				kptr = new KDF2(SHA2Digests::SHA256);
				break;
			}
			case Kdfs::KDF2512:
			{
				kptr = new KDF2(SHA2Digests::SHA512);
				break;
			}
			case Kdfs::PBKDF2256:
			{
				kptr = new PBKDF2(SHA2Digests::SHA256);
				break;
			}
			case Kdfs::PBKDF2512:
			{
				kptr = new PBKDF2(SHA2Digests::SHA512);
				break;
			}
			case Kdfs::SCRYPT256:
			{
				kptr = new SCRYPT(SHA2Digests::SHA256);
				break;
			}
			case Kdfs::SCRYPT512:
			{
				kptr = new SCRYPT(SHA2Digests::SHA512);
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
			case Kdfs::SHAKE1024:
			{
				kptr = new SHAKE(ShakeModes::SHAKE1024);
				break;
			}
			default:
			{
				throw CryptoException(std::string("KdfFromName"), std::string("GetInstance"), std::string("The kdf type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoKdfException &ex)
	{
		throw CryptoException(std::string("KdfFromName"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(std::string("KdfFromName"), std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
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
				kptr = new HKDF(SHA2Digests::SHA256);
				break;
			}
			case BlockCipherExtensions::HKDF512:
			{
				kptr = new HKDF(SHA2Digests::SHA512);
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
			case BlockCipherExtensions::SHAKE1024:
			{
				kptr = new SHAKE(ShakeModes::SHAKE1024);
				break;
			}
			default:
			{
				throw CryptoException(std::string("KdfFromName"), std::string("GetInstance"), std::string("The kdf type is not supported!"), ErrorCodes::InvalidParam);
			}
		}
	}
	catch (CryptoKdfException &ex)
	{
		throw CryptoException(std::string("KdfFromName"), std::string("GetInstance"), ex.Message(), ex.ErrorCode());
	}
	catch (const std::exception &ex)
	{
		throw CryptoException(std::string("KdfFromName"), std::string("GetInstance"), std::string(ex.what()), ErrorCodes::UnKnown);
	}

	return kptr;
}

NAMESPACE_HELPEREND
