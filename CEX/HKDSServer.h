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

#ifndef CEX_HKDSSERVER_H
#define CEX_HKDSSERVER_H

#include "CexDomain.h"
#include "CryptoAuthenticationFailure.h"
#include "CryptoKmsException.h"
#include "HKDSMasterKey.h"
#include "HkdsMessages.h"
#include "Kms.h"
#include "ShakeModes.h"

NAMESPACE_KMS

using Exception::CryptoAuthenticationFailure;
using Exception::CryptoKmsException;
using Enumeration::HkdsMessages;
using Enumeration::Kms;
using Enumeration::ShakeModes;

/// <summary>
/// Hierarchal Key Distribution System Server (HKDS-SERVER)
/// </summary>
///
/// <example>
/// <description>Server decrypts a client message</description>
/// <code>
/// // initialize the server with the client-ksn and master key
/// HKDSServer srv(mdk, KSN);
/// // server decrypts the message
/// srv.Decrypt(ctxt, ptxt);
/// </code>
/// 
/// <description>Create a clients device id</description>
/// <code>
/// // generate the clients embedded key
/// dk = HKDSServer::GenerateEdk(mdk.BDK, did);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B></B></description>
/// <para></para>
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
class HKDSServer final
{
private:

	static const size_t HKDS_CACHE_MULTIPLIER = 4;
	static const size_t HKDS_DID_SIZE = 12;
	static const size_t HKDS_KID_SIZE = 4;
	static const size_t HKDS_KSN_SIZE = 16;
	static const size_t HKDS_MESSAGE_SIZE = 16;
	static const size_t HKDS_NAME_SIZE = 7;
	static const size_t HKDS_TKC_SIZE = 4;
	static const size_t KMAC_CODE_SIZE = 16;
	static const size_t KMAC_KEY_SIZE = 16;

	class HKDSServerState;
	std::unique_ptr<HKDSServerState> m_hkdsServerState;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// The HKDS server constructor
	/// </summary>
	/// 
	/// <param name="Mdk">The base derivation key</param>
	/// <param name="Ksn">The clients identity string</param>
	HKDSServer(HKDSMasterKey &Mdk, const std::vector<byte> &Ksn);

	/// <summary>
	/// Finalize and destroy state
	/// </summary>
	~HKDSServer();

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The number of keys in a full cache
	/// </summary>
	const size_t KeyCacheSize();

	/// <summary>
	/// Read Only: The KMS server type name
	/// </summary>
	const Kms Enumeral();

	/// <summary>
	/// Read/Write: The clients key serial number
	/// </summary>
	std::vector<byte> &KSN();

	/// <summary>
	/// Read Only: The KMS formal implementation name
	/// </summary>
	const std::string Name();

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a message from the client
	/// </summary>
	/// 
	/// <param name="Input">The clients message cipher-text</param>
	/// <param name="Output">The client message plain-text</param>
	/// 
	/// <exception cref="CryptoKmsException">Thrown if the cipher-text size is invalid</exception>
	void Decrypt(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Verify a ciphertext's integrity with a keyed MAC, if verified return the decrypted PIN message.
	/// <para>This function uses KMAC to verify the cipher-text integrity before decrypting the message.
	/// An optional data can be added to the MAC update, such as the originating clients IP address.
	/// If the MAC verifies the cipher-text, the message is decrypted and returned by this function.
	/// If the MAC authentication check fails, a CryptoAuthenticationFailure exception is thrown.</para>
	/// </summary>
	///
	/// <param name="CipherText">The cipher-text with the appended MAC code</param>
	/// <param name="AdditionalData">The optional additional data used in authentication</param>
	/// 
	/// <returns>On success returns decrypted PIN message, on failure throws an exception</returns>
	///
	/// <exception cref="CryptoAuthenticationFailure">Thrown before decryption if the the ciphertext fails authentication</exception>
	/// <exception cref="CryptoKmsException">Thrown if the cipher-text size is invalid</exception>
	std::vector<byte> DecryptVerify(const std::vector<byte> &CipherText, const std::vector<byte> &AdditionalData);

	/// <summary>
	/// Generate a device key
	/// </summary>
	/// 
	/// <param name="Mdk">The base derivation key</param>
	/// <param name="DeviceId">The device identity string</param>
	/// 
	/// <returns>The device key</returns>
	static std::vector<byte> GenerateEdk(const std::vector<byte> &Mdk, const std::vector<byte> &DeviceId);

	/// <summary>
	/// Generate the HKDS key structure
	/// </summary>
	/// 
	/// <param name="Mode">The SHAKE mode</param>
	/// <param name="Mdk">The master key structure</param>
	/// <param name="Kid">The master keys identity string</param>
	static void GenerateMdk(ShakeModes Mode, HKDSMasterKey &Mdk, const std::vector<byte> &Kid);

	/// <summary>
	/// Encrypt the token key
	/// </summary>
	/// 
	/// <returns>The encrypted token key</returns>
	std::vector<byte> EncryptToken();

private:

	std::vector<byte> GenerateTransactionKey(size_t Length);
	std::vector<byte> GenerateToken(const std::vector<byte> &STK, const std::vector<byte> &Ksn);
	std::vector<byte> GetCtok();
	static ShakeModes ModeFromID(const std::vector<byte> &Did);
};

NAMESPACE_KMSEND
#endif
