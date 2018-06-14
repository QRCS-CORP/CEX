#include "KdfFromName.h"
#include "Digests.h"
#include "HKDF.h"
#include "KDF2.h"
#include "PBKDF2.h"
#include "SCRYPT.h"
#include "SHAKE.h"

NAMESPACE_HELPER

IKdf* KdfFromName::GetInstance(Kdfs KdfType)
{
	IKdf* kdfPtr = nullptr;

	try
	{
		switch (KdfType)
		{
			case Kdfs::HKDF256:
			{
				kdfPtr = new Kdf::HKDF(Enumeration::Digests::SHA256);
				break;
			}
			case Kdfs::HKDF512:
			{
				kdfPtr = new Kdf::HKDF(Enumeration::Digests::SHA512);
				break;
			}
			case Kdfs::KDF2256:
			{
				kdfPtr = new Kdf::KDF2(Enumeration::Digests::SHA256);
				break;
			}
			case Kdfs::KDF2512:
			{
				kdfPtr = new Kdf::KDF2(Enumeration::Digests::SHA512);
				break;
			}
			case Kdfs::PBKDF2256:
			{
				kdfPtr = new Kdf::PBKDF2(Enumeration::Digests::SHA256);
				break;
			}
			case Kdfs::PBKDF2512:
			{
				kdfPtr = new Kdf::PBKDF2(Enumeration::Digests::SHA512);
				break;
			}
			case Kdfs::SCRYPT256:
			{
				kdfPtr = new Kdf::SCRYPT(Enumeration::Digests::SHA256);
				break;
			}
			case Kdfs::SCRYPT512:
			{
				kdfPtr = new Kdf::SCRYPT(Enumeration::Digests::SHA512);
				break;
			}
			case Kdfs::SHAKE128:
			{
				kdfPtr = new Kdf::SHAKE(Enumeration::ShakeModes::SHAKE128);
				break;
			}
			case Kdfs::SHAKE256:
			{
				kdfPtr = new Kdf::SHAKE(Enumeration::ShakeModes::SHAKE256);
				break;
			}
			case Kdfs::SHAKE512:
			{
				kdfPtr = new Kdf::SHAKE(Enumeration::ShakeModes::SHAKE512);
				break;
			}
			case Kdfs::SHAKE1024:
			{
				kdfPtr = new Kdf::SHAKE(Enumeration::ShakeModes::SHAKE1024);
				break;
			}
			default:
			{
				throw CryptoException("KdfFromName:GetInstance", "The kdf type is not recognized!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("KdfFromName:GetInstance", "The kdf is unavailable!", std::string(ex.what()));
	}

	return kdfPtr;
}

NAMESPACE_HELPEREND
