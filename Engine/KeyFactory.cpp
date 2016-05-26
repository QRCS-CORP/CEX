#include "KeyFactory.h"
#include "CryptoProcessingException.h"
#include "CSPRsg.h"
#include "KeyGenerator.h"

NAMESPACE_PRCFACTORY

void KeyFactory::Create(CEX::Common::CipherDescription &Description, CEX::Enumeration::SeedGenerators SeedEngine, CEX::Enumeration::Digests HashEngine)
{
	CEX::Seed::CSPRsg rnd;
	CEX::Common::KeyGenerator keyGen(SeedEngine, HashEngine, rnd.GetBytes(16));
	CEX::Common::KeyParams* key = keyGen.GetKeyParams(Description.KeySize(), (uint)Description.IvSize(), Description.MacKeySize());

	Create(Description, *key);
}

void KeyFactory::Create(CEX::Common::CipherDescription &Description, CEX::Common::KeyParams &KeyParam)
{
	if (KeyParam.Key().size() != Description.KeySize())
		throw CEX::Exception::CryptoProcessingException("KeyFactory:Create", "The key parameter does not match the key size specified in the Header!");

	if ((uint)Description.IvSize() > 0)
	{
		if (KeyParam.IV().size() != (uint)Description.IvSize())
			throw CEX::Exception::CryptoProcessingException("KeyFactory:Create", "The KeyParam IV size does not align with the IVSize setting in the Header!");
	}
	if (Description.MacKeySize() > 0)
	{
		if (KeyParam.Ikm().size() != Description.MacKeySize())
			throw CEX::Exception::CryptoProcessingException("KeyFactory:Create", "Header MacKeySize does not align with the size of the KeyParam IKM!");
	}

	CEX::Seed::CSPRsg rnd;
	CEX::Processing::Structure::CipherKey ck(Description, rnd.GetBytes(16), rnd.GetBytes(16));
	std::vector<byte> hdr = ck.ToBytes();
	m_keyStream->Write(hdr, 0, hdr.size());
	CEX::IO::MemoryStream* tmp = CEX::Common::KeyParams::Serialize(KeyParam);
	std::vector<byte> key = tmp->ToArray();
	m_keyStream->Write(key, 0, key.size());
	delete tmp;
}

void KeyFactory::Create(CEX::Common::KeyParams &KeyParam, CEX::Enumeration::SymmetricEngines EngineType, int KeySize, CEX::Enumeration::IVSizes IvSize, 
	CEX::Enumeration::CipherModes CipherType, CEX::Enumeration::PaddingModes PaddingType, CEX::Enumeration::BlockSizes BlockSize, 
	CEX::Enumeration::RoundCounts Rounds, CEX::Enumeration::Digests KdfEngine, int MacKeySize, CEX::Enumeration::Digests MacEngine)
{
	CEX::Common::CipherDescription dsc(
		EngineType,
		KeySize,
		IvSize,
		CipherType,
		PaddingType,
		BlockSize,
		Rounds,
		KdfEngine,
		MacKeySize,
		MacEngine);

	Create(dsc, KeyParam);
}

void KeyFactory::Extract(CEX::Processing::Structure::CipherKey &KeyHeader, CEX::Common::KeyParams &KeyParam)
{
	KeyHeader = CEX::Processing::Structure::CipherKey(*m_keyStream);
	const CEX::Common::CipherDescription dsc = KeyHeader.Description();

	if (m_keyStream->Length() < dsc.KeySize() + (uint)dsc.IvSize() + dsc.MacKeySize() + KeyHeader.GetHeaderSize())
		throw CEX::Exception::CryptoProcessingException("KeyFactory:Extract", "The size of the key file does not align with the CipherKey sizes! Key is corrupt.");

	m_keyStream->Seek(KeyHeader.GetHeaderSize(), CEX::IO::SeekOrigin::Begin);
	KeyParam = *CEX::Common::KeyParams::DeSerialize(*m_keyStream);
}

NAMESPACE_PRCFACTORYEND
