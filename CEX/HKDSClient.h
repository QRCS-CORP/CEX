// 2020 Digital Freedom Defense Incorporated
// All Rights Reserved.
// Patent pending on this software and algorithm design.
// 
// NOTICE:  All information contained herein is, and remains
// the property of Digital Freedom Defense Incorporated.  
// The intellectual and technical concepts contained
// herein are proprietary to Digital Freedom Defense Incorporated
// and its suppliers and may be covered by U.S. and Foreign Patents,
// patents in process, and are protected by trade secret or copyright law.
// Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained
// from Digital Freedom Defense Incorporated.
//
// Written by John G. Underhill
// Updated by March 23, 2020
// Contact: develop@dfdef.com

#ifndef CEX_HKDSCLIENT_H
#define CEX_HKDSCLIENT_H

#include "CexDomain.h"
#include "CryptoKmsException.h"
#include "HkdsMessages.h"
#include "Kms.h"
#include "ShakeModes.h"

NAMESPACE_KMS

using Enumeration::ErrorCodes;
using Exception::CryptoKmsException;
using Enumeration::HkdsMessages;
using Enumeration::Kms;
using Enumeration::ShakeModes;

/// <summary>
/// Hierarchal Key Distribution System Client (HKDS-CLIENT)
/// </summary>
///
/// <example>
/// <description>Client token exchange</description>
/// <code>
/// // initialize the client
/// HKDSClient clt(dk, did);
/// 
/// // initialize the server with the client-ksn
/// HKDSServer srv(mdk, clt.KSN());
/// 
/// // client requests the token key from server
/// etok = srv.EncryptToken();
/// 
/// // client decrypts the token
/// dtok = clt.DecryptToken(etok);
/// 
/// // client derives the transaction key-set
/// clt.GenerateKeyCache(dtok);
/// </code>
/// </example>
/// 
/// <example>
/// <description>Client token exchange</description>
/// <code>
/// // initialize the client
/// HKDSClient clt(dk, did);
/// 
/// // initialize the server with the client-ksn
/// HKDSServer srv(mdk, clt.KSN());
/// 
/// // client requests the token key from server
/// etok = srv.EncryptToken();
/// 
/// // client decrypts the token
/// dtok = clt.DecryptToken(etok);
/// 
/// // client derives the transaction key-set
/// clt.GenerateKeyCache(dtok);
/// </code>
///
/// <code>
/// // client encrypts a message
/// clt.Encrypt(msg, cpt);
/// </code>
/// </example>
/// 
/// <description>Implementation Notes:</description>
/// <para>The HKDS key management protocol, utilized in conjunction with the Keccak family of message authentication code generators(KMAC), 
/// and extended output functions(SHAKE), is used to derive unique symmetric keys employed to protect messaging in a financial services environment.
/// The security of a distributed key scheme is directly tied to the secure derivation of transaction keys, used to encrypt a message cryptogram.
/// This specification presents a distributed key management protocol that generates unique transaction keys from a base terminal key, in such a way that:</para>
/// <list type="bullet">
/// <item><description>The terminal does not retain information that could be used to reconstruct the key once the transaction has been completed(forward security).</description></item>
/// <item><description>The capture of the terminals state, does not provide enough information to construct future derived keys(predicative resistance).</description></item>
/// <item><description>The server can reconstruct the transaction key using a bonded number of cryptographic operations.</description></item>
/// </list>
/// <para>HKDS is a two-key system.It uses an embedded key on the client to encrypt token exchanges and as a portion of the key used to generate the transaction key cache.It also uses a token key; 
/// an ephemeral key derived by the server, encrypted and sent to the client, as the second part of the key used to initialize the PRF that generates the transaction key cache.
/// There are numerous advantages to using two keys in this way:</para>
/// <list type="bullet">
/// <item><description>The client’s embedded device key need never be updated, the base token key can be updated instead, to inject new entropy into the system.</description></item>
/// <item><description>The client can produce a practically unlimited number of derived transaction keys, there is no upper limit, so long as the base token key is periodically refreshed 
/// (after many thousands of token derivations, or millions of transactions).</description></item>
/// <item><description>This method provides both forward security, and predictive resistance. 
/// Even if the client’s state is captured, the adversary will not be able to derive past key caches from the information contained in the state.
/// Likewise, the adversary will not be able to derive future key caches based on the captured state alone.</description></item>
/// <item><description>The client’s key can be changed, without changing the embedded key itself (which is usually stored in a tamper-proof module, and can only be changed via direct access to the terminal). 
/// The client’s master key identity can be changed instead, pointing to a different master key, that derives the same embedded device key, but uses a different base secret token.</description></item>
/// <item><description>Performance: HKDS is highly efficient, outperforming DUKPT-AES by 4 times the decryption speed with a 128-bit key, to as much as 8 times faster than DUKPT using a 256-bit key, 
/// and we believe if using embedded Keccak CPU instructions, the performance of HKDS can be vastly improved upon.</description></item>
/// <item><description>Security: HKDS can be implemented with 128, 256, and 512-bit security settings, and uses strong standardized(KMAC) authentication.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>FIPS 202: <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">Permutation Based Hash</a> and Extendable Output Functions</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SP800-185</a> SHA-3 Derived Functions.</description></item>
/// <item><description>Team Keccak <a href="https://keccak.team/index.html">Homepage</a>.</description></item>
/// </list>
/// </remarks>
class HKDSClient final
{
private:

   /* The transaction key cache multiplier.
	* Changes the size of the transaction key cache.
	* Must be a multiple of 2; allowed size are 2, 4, 6, 8, 10, and 12.
	* A larger cache means fewer token exchanges, but a slower decryption,
	* and a larger client cache size.
	* The recommended value is 4, and not exceeding 8.*/
	static const size_t HKDS_CACHE_MULTIPLIER = 4;
	static const size_t HKDS_DID_SIZE = 12;
	static const size_t HKDS_KID_SIZE = 4;
	static const size_t HKDS_KSN_SIZE = 16;
	static const size_t HKDS_MESSAGE_SIZE = 16;
	static const size_t HKDS_NAME_SIZE = 7;
	static const size_t HKDS_TKC_SIZE = 4;
	static const size_t KMAC_CODE_SIZE = 16;

	class HKDSClientState;
	std::unique_ptr<HKDSClientState> m_hkdsClientState;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// The HKDS client constructor
	/// </summary>
	/// 
	/// <param name="Edk">The embedded device key</param>
	/// <param name="Did">The devices unique identity string</param>
	HKDSClient(const std::vector<byte> &Edk, const std::vector<byte> &Did);

	/// <summary>
	/// Finalize and destroy state
	/// </summary>
	~HKDSClient();

	//~~~Accessors~~~//

	/// <summary>
	/// Decrypt a token key
	/// </summary>
	/// 
	/// <param name="Token">The decrypted token key</param>
	std::vector<byte> DecryptToken(const std::vector<byte> &Token);

	/// <summary>
	/// Read Only: The number of keys in a full cache
	/// </summary>
	const size_t KeyCacheSize();

	/// <summary>
	/// Read Only: The number of available transaction keys in the cache
	/// </summary>
	const size_t KeyCount();

	/// <summary>
	/// Read Only: The KMS enumeration type name
	/// </summary>
	const Kms Enumeral();

	/// <summary>
	/// Read Only: The key serial number
	/// </summary>
	std::vector<byte> KSN();

	/// <summary>
	/// Read Only: The KMS formal implementation name
	/// </summary>
	const std::string Name();

	//~~~Public Functions~~~//

	/// <summary>
	/// Encrypt a message
	/// </summary>
	/// 
	/// <param name="Message">The input plain-text</param>
	/// <param name="CipherText">The output cipher-text</param>
	void Encrypt(const std::vector<byte> &Message, std::vector<byte> &CipherText);

	/// <summary>
	/// Encrypt and authenticate a PIN message.
	/// <para>The PIN is first encrypted, then the cipher-text is used to update a keyed KMAC function.
	/// An optional data can be added to the MAC update, such as the IP address of the client. 
	/// The authentication tag is appended to the encrypted PIN and returned by the function.</para>
	/// </summary>
	///
	/// <param name="Message">The PIN message to encrypt</param>
	/// <param name="AdditionalData">The optional additional data used in authentication</param>
	/// 
	/// <returns>The encrypted message and appended authentication code</returns>
	std::vector<byte> EncryptAuthenticate(const std::vector<byte> &Message, const std::vector<byte> &AdditionalData);

	/// <summary>
	/// Generate the key-cache
	/// </summary>
	///
	/// <param name="Token">The token key</param>
	void GenerateKeyCache(std::vector<byte> &Token);

private:

	std::vector<byte> GenerateTransactionKey();
	static ShakeModes ModeFromID(const std::vector<byte> &Did);
};

NAMESPACE_KMSEND
#endif
