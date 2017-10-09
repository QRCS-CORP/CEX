#include "RingLWE.h"

NAMESPACE_RINGLWE

//using Cipher::Asymmetric::RLWE::FFTQ7681N256;

const std::string RingLWE::CLASS_NAME = "RingLWE";

/*IAsymmetricKeyPair* RingLWE::Generate()
{
	FFTQ7681N256 nnt(m_rndGenerator);
	return nnt.Generate();
}

void RingLWE::Decrypt(std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	FFTQ7681N256 nnt(m_rndGenerator);
	nnt.Decrypt(m_privateKey, Input, InOffset, Output, OutOffset);
}

void RingLWE::Encrypt(std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	FFTQ7681N256 nnt(m_rndGenerator);
	nnt.Encrypt(m_publicKey, Input, InOffset, Output, OutOffset);
}*/

NAMESPACE_RINGLWEEND