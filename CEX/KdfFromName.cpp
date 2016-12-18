#include "KdfFromName.h"
#include "HKDF.h"
#include "KDF2.h"
#include "PBKDF2.h"

NAMESPACE_HELPER

IKdf* KdfFromName::GetInstance(Kdfs KdfType, Digests DigestType)
{
	if (DigestType == Digests::None)
		throw Exception::CryptoException("KdfFromName:GetInstance", "The digest type can not be set to None!");

	try
	{
		switch (KdfType)
		{
		case Kdfs::HKDF:
			return new Kdf::HKDF(DigestType);
			break;
		case Kdfs::KDF2:
			return new Kdf::KDF2(DigestType);
			break;
		case Kdfs::PBKDF2:
			return new Kdf::PBKDF2(DigestType);
			break;
		default:
			throw Exception::CryptoException("KdfFromName:GetInstance", "The kdf type is not recognized!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("KdfFromName:GetInstance", "The kdf is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND