#include "PaddingFromName.h"
#include "ISO7816.h"
#include "PKCS7.h"
#include "TBC.h"
#include "X923.h"

NAMESPACE_HELPER

IPadding* PaddingFromName::GetInstance(PaddingModes PaddingType)
{
	IPadding* padPtr;

	try
	{
		switch (PaddingType)
		{
			case PaddingModes::ISO7816:
			{
				padPtr = new Cipher::Symmetric::Block::Padding::ISO7816();
				break;
			}
			case PaddingModes::PKCS7:
			{
				padPtr = new Cipher::Symmetric::Block::Padding::PKCS7();
				break;
			}
			case PaddingModes::TBC:
			{
				padPtr = new Cipher::Symmetric::Block::Padding::TBC();
				break;
			}
			case PaddingModes::X923:
			{
				padPtr = new Cipher::Symmetric::Block::Padding::X923();
				break;
			}
			default:
			{
				throw CryptoException("PaddingFromName:GetPadding", "The padding mode is not recognized!");
			}
		}
	}
	catch (const std::exception &ex)
	{
		throw CryptoException("PaddingFromName:GetInstance", "The padding mode is unavailable!", std::string(ex.what()));
	}

	return padPtr;
}

NAMESPACE_HELPEREND