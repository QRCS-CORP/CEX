#include "Dilithium.h"

NAMESPACE_ASYMMETRICSIGN

Dilithium::Dilithium()
{

}

Dilithium::~Dilithium()
{

}

const AsymmetricEngines Dilithium::Enumeral()
{
	return AsymmetricEngines::Dilithium;
}

const bool Dilithium::IsInitialized()
{
	return false;
}

const bool Dilithium::IsSigner()
{
	return false;
}

const std::string Dilithium::Name()
{
	return std::string("");
}

const void Dilithium::Initialize(IAsymmetricKey* AsymmetricKey)
{

}

size_t Dilithium::Sign(const std::vector<byte> &Message, std::vector<byte> &Signature)
{
	return 0;
}

bool Dilithium::Verify(const std::vector<byte> &Signature, std::vector<byte> &Message)
{
	return false;
}

NAMESPACE_ASYMMETRICSIGNEND