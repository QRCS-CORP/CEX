#include "PaddingFromName.h"
#include "ISO7816.h"
#include "PKCS7.h"
#include "TBC.h"
#include "X923.h"

NAMESPACE_HELPER

CEX::Cipher::Symmetric::Block::Padding::IPadding* PaddingFromName::GetInstance(CEX::Enumeration::PaddingModes PaddingType)
{
	switch (PaddingType)
	{
		case CEX::Enumeration::PaddingModes::ISO7816:
			return new CEX::Cipher::Symmetric::Block::Padding::ISO7816();
		case CEX::Enumeration::PaddingModes::PKCS7:
			return new CEX::Cipher::Symmetric::Block::Padding::PKCS7();
		case CEX::Enumeration::PaddingModes::TBC:
			return new CEX::Cipher::Symmetric::Block::Padding::TBC();
		case CEX::Enumeration::PaddingModes::X923:
			return new CEX::Cipher::Symmetric::Block::Padding::X923();
		default:
			throw CEX::Exception::CryptoException("PaddingFromName:GetPadding", "The padding mode is not recognized!");
	}
}

NAMESPACE_HELPEREND