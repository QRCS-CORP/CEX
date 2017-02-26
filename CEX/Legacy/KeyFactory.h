#ifndef _CEXENGINE_KEYFACTORY_H
#define _CEXENGINE_KEYFACTORY_H

#include "CexDomain.h"
#include "BlockSizes.h"
#include "CipherDescription.h"
#include "CipherKey.h"
#include "CipherModes.h"
#include "Digests.h"
#include "IVSizes.h"
#include "MemoryStream.h"
#include "PaddingModes.h"
#include "Providers.h"
#include "RoundCounts.h"
#include "SymmetricEngines.h"
#include "SymmetricKey.h"

NAMESPACE_PRCFACTORY

using Enumeration::BlockSizes;
using Processing::Structure::CipherDescription;
using Processing::Structure::CipherKey;
using Enumeration::CipherModes;
using Enumeration::Digests;
using Enumeration::IVSizes;
using IO::MemoryStream;
using Enumeration::PaddingModes;
using Enumeration::Providers;
using Enumeration::RoundCounts;
using Enumeration::SymmetricEngines;
using Key::Symmetric::SymmetricKey;

/// <summary>
/// Used to create or extract a CipherKey file.
/// 
/// <list type="bullet">
/// <item><description>The Constructor requires a pointer to a MemoryStream for reading or writing; using Create() objects are written to the stream, with Extract() objects are read from the stream.</description></item>
/// <item><description>The Create(CipherDescription, SymmetricKey) method requires a populated CipherDescription and SymmetricKey class.</description></item>
/// <item><description>The Create(CipherDescription, Providers, Digests) method will auto-generate keying material.</description></item>
/// <item><description>The Extract() method retrieves a populated cipher key (CipherKey), and key material (SymmetricKey), from the key stream.</description></item>
/// </list>
/// </summary>
/// 
/// <example>
/// <description>Example using the Create() and Extract methods:</description>
/// <code>
/// KeyGenerator kg;
/// SymmetricKey kp = *kg.GetKeyParams(192, 16, 64);
/// // out-bound funcs use pointer
/// MemoryStream* m = new MemoryStream;
/// Processing::KeyFactory kf(m);
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
/// SymmetricKey kp2;
/// m->Seek(0, IO::SeekOrigin::Begin);
/// Processing::CipherKey ck;
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
class KeyFactory
{
private:
	bool m_isDestroyed;
	MemoryStream* m_keyStream;

	KeyFactory() {}

public:

	/// <summary>
	/// Instantiate this class with a memory stream; key will be written to the stream
	/// </summary>
	/// 
	/// <param name="KeyStream">The fully qualified path to the key file to be read or created</param>
	explicit KeyFactory(MemoryStream* KeyStream)
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
	/// <para>The Key, and optional Nonce and Info are generated automatically using the cipher description contained in the CipherDescription.
	/// This overload creates keying material using the seed and digest engines specified with the KeyGenerator class</para>
	/// </summary>
	/// 
	/// <param name="Description">The Cipher Description containing the cipher implementation details</param>
	/// <param name="SeedEngine">The Random Generator used to create the stage I seed material during key generation.</param>
	/// <param name="HashEngine">The Digest Engine used in the stage II phase of key generation.</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if a SymmetricKey member is null, but specified in the Header</exception>
	void Create(CipherDescription &Description, Providers ProviderType = Providers::CSP, Digests HashEngine = Digests::SHA512);

	/// <summary>
	/// Create a single use key file using a SymmetricKey containing the key material, and a CipherDescription containing the cipher implementation details
	/// </summary>
	/// 
	/// <param name="Description">The Cipher Description containing the cipher details</param>
	/// <param name="KeyParam">An initialized and populated key material container</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if a SymmetricKey member is null, but specified in the Header or a Header parameter does not match a SymmetricKey value</exception>
	void Create(CipherDescription &Description, SymmetricKey &KeyParam);

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
	void Create(SymmetricKey &KeyParam, SymmetricEngines EngineType, int KeySize, IVSizes IvSize, CipherModes CipherType, PaddingModes PaddingType, 
		BlockSizes BlockSize, RoundCounts Rounds, Digests KdfEngine, int MacKeySize, Digests MacEngine);

	/// <summary>
	/// Extract a SymmetricKey and CipherKey
	/// </summary>
	/// 
	/// <param name="KeyHeader">The CipherKey that receives the cipher description, key id, and extension key</param>
	/// <param name="KeyParam">The SymmetricKey container that receives the key material from the file</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if the key file could not be found or a Header parameter does not match the keystream length</exception>
	void Extract(CipherKey &KeyHeader, SymmetricKey &KeyParam);
};

NAMESPACE_PRCFACTORYEND
#endif