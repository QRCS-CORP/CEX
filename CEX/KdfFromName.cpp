#include "KdfFromName.h"
#include "HKDF.h"
#include "KDF2.h"
#include "PBKDF2.h"

NAMESPACE_HELPER

IKdf* KdfFromName::GetInstance(Kdfs KdfType, Digests DigestType)
{
	if (DigestType == Digests::None)
	{
		throw CryptoException("KdfFromName:GetInstance", "The digest type can not be set to None!");
	}

	IKdf* kdfPtr;

	try
	{
		switch (KdfType)
		{
			case Kdfs::HKDF:
			{
				kdfPtr = new Kdf::HKDF(DigestType);
				break;
			}
			case Kdfs::KDF2:
			{
				kdfPtr = new Kdf::KDF2(DigestType);
				break;
			}
			case Kdfs::PBKDF2:
			{
				kdfPtr = new Kdf::PBKDF2(DigestType);
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