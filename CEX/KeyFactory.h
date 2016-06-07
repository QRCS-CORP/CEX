#ifndef _CEXENGINE_KEYFACTORY_H
#define _CEXENGINE_KEYFACTORY_H

#include "Common.h"
#include "CipherKey.h"
#include "KeyParams.h"
#include "MemoryStream.h"
#include "SeedGenerators.h"

NAMESPACE_PRCFACTORY

/// <summary>
/// KeyFactory: Used to create or extract a CipherKey file.
/// 
/// <list type="bullet">
/// <item><description>The Constructor requires a pointer to a MemoryStream for reading or writing; using Create() objects are written to the stream, with Extract() objects are read from the stream.</description></item>
/// <item><description>The Create(CipherDescription, KeyParams) method requires a populated CipherDescription and KeyParams class.</description></item>
/// <item><description>The Create(CipherDescription, SeedGenerators, Digests) method will auto-generate keying material.</description></item>
/// <item><description>The Extract() method retrieves a populated cipher key (CipherKey), and key material (KeyParams), from the key stream.</description></item>
/// </list>
/// </summary>
/// 
/// <example>
/// <description>Example using the Create() and Extract methods:</description>
/// <code>
/// KeyGenerator kg;
/// KeyParams kp = *kg.GetKeyParams(192, 16, 64);
/// // out-bound funcs use pointer
/// MemoryStream* m = new MemoryStream;
/// CEX::Processing::KeyFactory kf(m);
/// 
/// CipherDescription ds(
/// 	SymmetricEngines::RHX,
/// 	192,
/// 	IVSizes::V128,
/// 	CipherModes::CTR,
/// 	PaddingModes::PKCS7,
/// 	BlockSizes::B128,
/// 	RoundCounts::R22,
/// 	Digests::Skein512,
/// 	64,
/// 	Digests::SHA512);
/// 
/// kf.Create(ds, kp);
/// KeyParams kp2;
/// m->Seek(0, CEX::IO::SeekOrigin::Begin);
/// CEX::Processing::CipherKey ck;
/// kf.Extract(ck, kp2);
/// 
/// if (!ds.Equals(ck.Description()))
///		throw;
/// if (!kp.Equals(kp2))
///		throw;
/// 
/// delete m;
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Processing::Structure::CipherKey"/>
/// <seealso cref="CEX::Common::CipherDescription"/>
/// <seealso cref="CEX::Enumeration::Prngs"/>
/// <seealso cref="CEX::Enumeration::Digests"/>
/// <seealso cref="CEX::Common::KeyParams"/>
class KeyFactory
{
private:
	bool m_isDestroyed;
	CEX::IO::MemoryStream* m_keyStream;

	KeyFactory() {}

public:

	/// <summary>
	/// Initialize this class with a memory stream; key will be written to the stream
	/// </summary>
	/// 
	/// <param name="KeyStream">The fully qualified path to the key file to be read or created</param>
	explicit KeyFactory(CEX::IO::MemoryStream* KeyStream)
		:
		m_isDestroyed(false),
		m_keyStream(KeyStream)
	{
	}

	/// <summary>
	/// Finalizer: ensure resources are destroyed
	/// </summary>
	~KeyFactory()
	{
	}

	/// <summary>
	/// Create a single use key file using automatic key material generation.
	/// <para>The Key, and optional IV and IKM are generated automatically using the cipher description contained in the CipherDescription.
	/// This overload creates keying material using the seed and digest engines specified with the KeyGenerator class</para>
	/// </summary>
	/// 
	/// <param name="Description">The Cipher Description containing the cipher implementation details</param>
	/// <param name="SeedEngine">The Random Generator used to create the stage I seed material during key generation.</param>
	/// <param name="HashEngine">The Digest Engine used in the stage II phase of key generation.</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if a KeyParams member is null, but specified in the Header</exception>
	void Create(CEX::Common::CipherDescription &Description, CEX::Enumeration::SeedGenerators SeedEngine = CEX::Enumeration::SeedGenerators::CSPRsg, CEX::Enumeration::Digests HashEngine = CEX::Enumeration::Digests::SHA512);

	/// <summary>
	/// Create a single use key file using a KeyParams containing the key material, and a CipherDescription containing the cipher implementation details
	/// </summary>
	/// 
	/// <param name="Description">The Cipher Description containing the cipher details</param>
	/// <param name="KeyParam">An initialized and populated key material container</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if a KeyParams member is null, but specified in the Header or a Header parameter does not match a KeyParams value</exception>
	void Create(CEX::Common::CipherDescription &Description, CEX::Common::KeyParams &KeyParam);

	/// <summary>
	/// Create a single use Key file using a manual description of the cipher parameters.
	/// </summary>
	/// 
	/// <param name="KeyParam">An initialized and populated key material container</param>
	/// <param name="EngineType">The Cryptographic Engine type</param>
	/// <param name="KeySize">The cipher Key Size in bytes</param>
	/// <param name="IvSize">Size of the cipher Initialization Vector</param>
	/// <param name="CipherType">The type of Cipher Mode</param>
	/// <param name="PaddingType">The type of cipher Padding Mode</param>
	/// <param name="BlockSize">The cipher Block Size</param>
	/// <param name="Rounds">The number of diffusion Rounds</param>
	/// <param name="KdfEngine">The Digest engine used to power the key schedule Key Derivation Function in HX ciphers</param>
	/// <param name="MacKeySize">The size of the HMAC key in bytes; a zeroed parameter means authentication is not enabled with this key</param>
	/// <param name="MacEngine">The HMAC Digest engine used to authenticate a message file encrypted with this key</param>
	void Create(CEX::Common::KeyParams &KeyParam, CEX::Enumeration::SymmetricEngines EngineType, int KeySize, CEX::Enumeration::IVSizes IvSize, 
		CEX::Enumeration::CipherModes CipherType, CEX::Enumeration::PaddingModes PaddingType, CEX::Enumeration::BlockSizes BlockSize, 
		CEX::Enumeration::RoundCounts Rounds, CEX::Enumeration::Digests KdfEngine, int MacKeySize, CEX::Enumeration::Digests MacEngine);

	/// <summary>
	/// Extract a KeyParams and CipherKey
	/// </summary>
	/// 
	/// <param name="KeyHeader">The CipherKey that receives the cipher description, key id, and extension key</param>
	/// <param name="KeyParam">The KeyParams container that receives the key material from the file</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if the key file could not be found or a Header parameter does not match the keystream length</exception>
	void Extract(CEX::Processing::Structure::CipherKey &KeyHeader, CEX::Common::KeyParams &KeyParam);
};

NAMESPACE_PRCFACTORYEND
#endif