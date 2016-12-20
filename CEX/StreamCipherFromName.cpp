#include "StreamCipherFromName.h"
#include "ChaCha20.h"
#include "Salsa20.h"

NAMESPACE_HELPER

IStreamCipher* StreamCipherFromName::GetInstance(StreamCiphers StreamCipherType, uint RoundCount)
{
	try
	{
		switch (StreamCipherType)
		{
		case StreamCiphers::ChaCha20:
			return new Cipher::Symmetric::Stream::ChaCha20(RoundCount);
		case StreamCiphers::Salsa:
			return new Cipher::Symmetric::Stream::Salsa20(RoundCount);
		default:
			throw Exception::CryptoException("StreamCipherFromName:GetStreamEngine", "The stream cipher is not recognized!");
		}
	}
	catch (const std::exception &ex)
	{
		throw Exception::CryptoException("StreamCipherFromName:GetInstance", "The stream cipher is unavailable!", std::string(ex.what()));
	}
}

NAMESPACE_HELPEREND