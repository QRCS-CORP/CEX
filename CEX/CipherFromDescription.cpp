#include "CipherFromDescription.h"
#include "BlockCipherFromName.h"
#include "CryptoException.h"
#include "CipherModeFromName.h"

NAMESPACE_HELPER

using Enumeration::SymmetricEngines;

ICipherMode* CipherFromDescription::GetInstance(CipherDescription &Description)
{
	try
	{
		switch (Description.EngineType())
		{
		case SymmetricEngines::AHX:
		case SymmetricEngines::RHX:
		case SymmetricEngines::SHX:
		case SymmetricEngines::THX:
		{
			return Helper::CipherModeFromName::GetInstance(Description.CipherType(),
				Helper::BlockCipherFromName::GetInstance((Enumeration::BlockCiphers)Description.EngineType(),
					(uint)Description.BlockSize(), (uint)Description.RoundCount(), Description.KdfEngine()));
		}
		default:
			throw Exception::CryptoException("CipherFromDescription:GetInstance", "The symmetric cipher is not recognized!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("CipherFromDescription:GetInstance", "The symmetric cipher type is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND