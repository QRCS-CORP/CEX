#include "PaddingFromName.h"
#include "ISO7816.h"
#include "PKCS7.h"
#include "TBC.h"
#include "X923.h"

NAMESPACE_HELPER

IPadding* PaddingFromName::GetInstance(PaddingModes PaddingType)
{
	try
	{
		switch (PaddingType)
		{
		case PaddingModes::ISO7816:
			return new Cipher::Symmetric::Block::Padding::ISO7816();
		case PaddingModes::PKCS7:
			return new Cipher::Symmetric::Block::Padding::PKCS7();
		case PaddingModes::TBC:
			return new Cipher::Symmetric::Block::Padding::TBC();
		case PaddingModes::X923:
			return new Cipher::Symmetric::Block::Padding::X923();
		default:
			throw Exception::CryptoException("PaddingFromName:GetPadding", "The padding mode is not recognized!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("PaddingFromName:GetInstance", "The padding mode is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND