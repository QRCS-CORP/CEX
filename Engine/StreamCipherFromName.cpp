#include "StreamCipherFromName.h"
#include "ChaCha.h"
#include "Salsa20.h"

NAMESPACE_HELPER

using namespace CEX::Cipher::Symmetric::Stream;

IStreamCipher* StreamCipherFromName::GetInstance(StreamCiphers EngineType, int RoundCount)
{
	switch (EngineType)
	{
		case StreamCiphers::ChaCha:
			return new ChaCha(RoundCount);
		case StreamCiphers::Salsa:
			return new Salsa20(RoundCount);
		default:
			throw CryptoException("StreamCipherFromName:GetStreamEngine", "The stream cipher is not recognized!");
	}
}

NAMESPACE_HELPEREND