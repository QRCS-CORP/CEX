#include "Picnic.h"

NAMESPACE_ASYMMETRICSIGN

Picnic::Picnic()
{

}

Picnic::~Picnic()
{

}

const AsymmetricEngines Picnic::Enumeral()
{
	return AsymmetricEngines::Picnic;
}

const bool Picnic::IsInitialized()
{
	return false;
}

const bool Picnic::IsSigner()
{
	return false;
}

const std::string Picnic::Name()
{
	return std::string("");
}

const void Picnic::Initialize(IAsymmetricKey &AsymmetricKey)
{

}

void Picnic::Reset()
{

}

void Picnic::Sign(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<byte> &Output, size_t OutOffset)
{

}

bool Picnic::Verify(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<byte> &Code)
{
	return false;
}

NAMESPACE_ASYMMETRICSIGNEND