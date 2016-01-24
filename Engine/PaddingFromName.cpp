#include "PaddingFromName.h"
#include "ISO7816.h"
#include "PKCS7.h"
#include "TBC.h"
#include "X923.h"

NAMESPACE_HELPER

using namespace CEX::Cipher::Symmetric::Block::Padding;

IPadding* PaddingFromName::GetInstance(PaddingModes PaddingType)
{
	switch (PaddingType)
	{
		case PaddingModes::ISO7816:
			return new ISO7816();
		case PaddingModes::PKCS7:
			return new PKCS7();
		case PaddingModes::TBC:
			return new TBC();
		case PaddingModes::X923:
			return new X923();
		default:
			throw CryptoException("PaddingFromName:GetPadding", "The padding mode is not recognized!");
	}
}

NAMESPACE_HELPEREND