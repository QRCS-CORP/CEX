#include "CipherFromDescription.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"

NAMESPACE_HELPER

ICipherMode* CipherFromDescription::GetInstance(CipherDescription &Description)
{
	try
	{
		return Helper::CipherModeFromName::GetInstance(Description.CipherType(),
			Helper::BlockCipherFromName::GetInstance(Description.EngineType(), Description.KdfEngine(), static_cast<uint>(Description.RoundCount())));
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("CipherFromDescription:GetInstance", "The symmetric cipher type is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND
