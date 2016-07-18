#include "StreamCipherFromName.h"
#include "ChaCha.h"
#include "Salsa20.h"

NAMESPACE_HELPER

CEX::Cipher::Symmetric::Stream::IStreamCipher* StreamCipherFromName::GetInstance(CEX::Enumeration::StreamCiphers StreamCipherType, uint RoundCount)
{
	switch (StreamCipherType)
	{
		case CEX::Enumeration::StreamCiphers::ChaCha:
			return new CEX::Cipher::Symmetric::Stream::ChaCha(RoundCount);
		case CEX::Enumeration::StreamCiphers::Salsa:
			return new CEX::Cipher::Symmetric::Stream::Salsa20(RoundCount);
		default:
#if defined(ENABLE_CPPEXCEPTIONS)
			throw CEX::Exception::CryptoException("StreamCipherFromName:GetStreamEngine", "The stream cipher is not recognized!");
#else
			return 0;
#endif
	}
}

NAMESPACE_HELPEREND