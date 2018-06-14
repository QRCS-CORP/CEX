#include "CipherFromDescription.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"

NAMESPACE_HELPER

ICipherMode* CipherFromDescription::GetInstance(CipherDescription &Description)
{
	IBlockCipher* cprPtr = nullptr;

	try
	{
		cprPtr = BlockCipherFromName::GetInstance(Description.CipherType(), Description.CipherExtensionType());

		return Helper::CipherModeFromName::GetInstance(cprPtr, Description.CipherModeType());
	}
	catch (const std::exception &ex)
	{
		if (cprPtr != nullptr)
		{
			delete cprPtr;
		}

		throw CryptoException("CipherFromDescription:GetInstance", "The symmetric cipher mode is invalid!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND
