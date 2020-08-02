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

#ifndef CEX_DUKPTSERVER_H
#define CEX_DUKPTSERVER_H

#include "CexDomain.h"
#include "CryptoAuthenticationFailure.h"
#include "CryptoKmsException.h"
#include "DukptDerivationPurpose.h"
#include "DukptKeyType.h"
#include "DukptKeyUsage.h"
#include "ECB.h"
#include "IntegerTools.h"

NAMESPACE_KMS

using Exception::CryptoAuthenticationFailure;
using Exception::CryptoKmsException;
using Cipher::Block::Mode::ECB;
using Enumeration::DukptDerivationPurpose;
using Enumeration::DukptKeyType;
using Enumeration::DukptKeyUsage;
using Enumeration::ErrorCodes;
using Tools::IntegerTools;

/// <summary>
/// DUKPTServer host state container
/// </summary>
class DukptServerState
{
public:

    std::vector<byte> DerivationData;
    std::vector<byte> DerivationKey;
    std::vector<byte> WorkingKey;

    DukptServerState()
        :
        DerivationData(0),
        DerivationKey(0),
        WorkingKey(0)
    {}

    ~DukptServerState()
    {
        IntegerTools::Clear(DerivationData);
        IntegerTools::Clear(DerivationKey);
        IntegerTools::Clear(WorkingKey);
    }
};

/// <summary>
/// A C++ implementation of the ANSI X9.24-3 2017 DUKPT-AES server host
/// </summary>
/// 
/// <example>
/// <description>Decrypting a PIN message:</description>
/// <code>
/// std::vector&lt;byte&gt; dec;
/// 
/// try
/// {
///     // check the message integrity, if it fails it throws without decrypting
///     dec = srv.DecryptPin(Bdk, Keyid, Ciphertext);
/// }
/// catch (CryptoKmsException const&)
/// {
///     // invalid ciphertext, do something..
/// }
/// </code>
///
/// <description>Verify and decrypt a PIN message:</description>
/// <code>
/// std::vector&lt;byte&gt; dec;
/// 
/// try
/// {
///     // check the message integrity, if it fails throw without decrypting
///     dec = srv.VerifyDecryptPin(Bdk, Keyid, Ciphertext, Data);
/// }
/// catch (CryptoAuthenticationFailure const&)
/// {
///     // authentication failed, do something..
/// }
/// catch (CryptoKmsException const&)
/// {
///     // invalid ciphertext, do something..
/// }
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>DUKPT is a key management standard, utilized in conjunction with the Advanced Encryption Standard (AES), 
/// to manage symmetric keys that can be used to protect messages and other sensitive information in a financial services environment.
/// It uses a Base Derivation Key (BDK) known only to the transaction processors, to derive intermediate keys (IPEK), 
/// that are then used unique device keys for point of sale devices.
/// The devices unique key is used to derive all future working keys, used by the device to encrypt PIN information,
/// sent back to the processing server along with a key identification string and a transaction count number, 
/// used to recreate the future key and decrypt the cryptogram.</para>
///
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>ANSI X9.24-3-2017: <a href="https://webstore.ansi.org/standards/ascx9/ansix9242017-1665702">Derived Unique Key Per Transaction: DUKPT-AES</a>.</description></item>
/// <item><description>ANSI X9.24-3-2017: <a href="https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Python-Source-20180129-1.pdf">Official Python implementation</a>.</description></item>
/// <item><description>ANSI X9.24-3-2017: <a href="https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Test-Vectors-20180129-1.pdf">Test vectors</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">AES Fips 197</a>.</description></item>
/// <item><description>HMAC <a href="http://tools.ietf.org/html/rfc2104">RFC 2104</a>.</description></item>
/// </list>
/// </remarks>
class DUKPTServer final
{
private:

    static const uint DUKPT_NUM_REG = 32;
    static const uint DUKPT_MAX_WORK = 16;
    static const size_t AES_BLOCK_SIZE = 16;
    static const size_t DUKPT_PIN_SIZE = 16;
    static const size_t HMAC_CODE_SIZE = 32;

    std::unique_ptr<Cipher::Block::Mode::ECB> m_ebcMode;

public:

    //~~~Constructor~~~//

    /// <summary>
    /// The DUKPTServer constructor
    /// </summary>
    DUKPTServer();

    /// <summary>
    /// The DUKPTServer destructor
    /// </summary>
    ~DUKPTServer();

    //~~~Public Functions~~~//

    /// <summary>
    /// Decrypt the PIN cipher-text
    /// </summary>
    ///
    /// <param name="Bdk">The base derivation key</param>
    /// <param name="KeyId">The key identity array and transaction counter</param>
    /// <param name="CipherText">The input cipher-text</param>
    /// 
    /// <returns>The decrypted PIN plain-text</returns>
    /// <exception cref="CryptoKmsException">Thrown if the cipher-text size is invalid</exception>
    std::vector<byte> Decrypt(const std::vector<byte> &Bdk, const std::vector<byte> &KeyId, const std::vector<byte> &CipherText);

    /// <summary>
    /// Verify a cipher-text's integrity with a keyed MAC, if verified return the decrypted PIN message.
    /// <para>This function uses HMAC(SHA2256) to verify the cipher-text integrity before decrypting the message.
    /// An optional data can be added to the MAC update, such as the originating clients IP address.
    /// If the MAC verifies the cipher-text, the message is decrypted and returned by this function.
    /// If the MAC authentication check fails, a CryptoAuthenticationFailure exception is thrown.</para>
    /// </summary>
    ///
    /// <param name="Bdk">The base derivation key</param>
    /// <param name="KeyId">The key identity array and transaction counter</param>
    /// <param name="CipherText">The cipher-text with the appended MAC code</param>
    /// <param name="AdditionalData">The optional additional data used in authentication</param>
    /// 
    /// <returns>On success returns decrypted PIN message, on failure throws an exception</returns>
    ///
    /// <exception cref="CryptoAuthenticationFailure">Thrown before decryption if the the ciphertext fails authentication</exception>
    /// <exception cref="CryptoKmsException">Thrown if the cipher-text size is invalid</exception>
    std::vector<byte> DecryptVerify(const std::vector<byte> &Bdk, const std::vector<byte> &KeyId, const std::vector<byte> &CipherText, 
        const std::vector<byte> &AdditionalData);

    /// <summary>
    /// B.5 Host Derive Working Key; derive a working key for a particular transaction based on a initial key-id and transaction counter
    /// </summary>
    ///
    /// <param name="State">The server state; contains the working and derivation keys and derivation data</param>
    /// <param name="Bdk">The base derivation key</param>
    /// <param name="WorkingKeyUsage">The key usage type</param>
    /// <param name="WorkingKeyType">The cipher key type</param>
    /// <param name="InitialKeyId">The initial key id</param>
    /// <param name="Counter">The transaction counter</param>
    /// 
    /// <returns>The working key structure</returns>
    void DeriveWorkingKey(DukptServerState &State, const std::vector<byte> &Bdk, DukptKeyUsage WorkingKeyUsage,
        DukptKeyType WorkingKeyType, const std::vector<byte> &InitialKeyId, uint Counter);

private:

    /// <summary>
    /// B.4.3 Create Derivation Data; compute derivation data for an AES DUKPTServer key derivation operation
    /// </summary>
    ///
    /// <param name="DerivationPurpose">The derived data purpose</param>
    /// <param name="KeyUsage">The data usage</param>
    /// <param name="DerivedKeyType">The key type</param>
    /// <param name="InitialKeyId">The initial key id</param>
    /// <param name="Counter">The transaction counter</param>
    /// 
    /// <returns>The derived data result array</returns>
    static std::vector<byte> CreateDerivationData(DukptDerivationPurpose DerivationPurpose, DukptKeyUsage KeyUsage,
        DukptKeyType DerivedKeyType, const std::vector<byte> &InitialKeyId, uint Counter);

    /// <summary>
    /// Decrypt plaintext with key using AES
    /// </summary>
    ///
    /// <param name="Key">The cipher key</param>
    /// <param name="CipherText">The input cipher-text</param>
    /// 
    /// <returns>The decrypted plain-text</returns>
    std::vector<byte> Decrypt(const std::vector<byte> &Key, const std::vector<byte> &CipherText);

    /// <summary>
    /// B.5 Derive Initial Key; derive the initial key for a particular initial key-id from a BDK
    /// </summary>
    ///
    /// <param name="Bdk">The base derivation key</param>
    /// <param name="KeyType">The cipher key type</param>
    /// <param name="InitialKeyId">The initial key id</param>
    /// 
    /// <returns>The initial key array</returns>
    std::vector<byte> DeriveInitialKey(const std::vector<byte> &Bdk, DukptKeyType KeyType, const std::vector<byte> &InitialKeyId);

    /// <summary>
    /// B.4.1 Derive Key algorithm; AES DUKPTServer key derivation function
    /// </summary>
    ///
    /// <param name="DerivationKey">The derivation key</param>
    /// <param name="KeyType">The selected key type</param>
    /// <param name="DerivationData">The derivation data</param>
    /// 
    /// <returns>The derived key result array</returns>
    std::vector<byte> DeriveKey(const std::vector<byte> &DerivationKey, DukptKeyType KeyType, std::vector<byte> &DerivationData);

    /// <summary>
    /// Encrypt plaintext with key using AES
    /// </summary>
    ///
    /// <param name="Key">The cipher key</param>
    /// <param name="PlainText">The input plain-text</param>
    /// 
    /// <returns>The encrypted cipher-text</returns>
    std::vector<byte> Encrypt(const std::vector<byte> &Key, const std::vector<byte> &PlainText);

    /// <summary>
    /// Convert a 32-bit integer to a list of bytes in big-endian order.
    /// Used to convert counter values to byte lists.
    /// </summary>
    ///
    /// <param name="X">The integer to convert</param>
    /// 
    /// <returns>The integer bytes</returns>
    static std::vector<byte> IntToBytes(uint X);

    /// <summary>
    /// B.3.2.Key Length function; length of an algorithm's key in bits
    /// </summary>
    ///
    /// <param name="KeyType">The base cipher key type</param>
    /// 
    /// <returns>The key size in bits</returns>
    static uint GetKeyLength(DukptKeyType KeyType);

};

NAMESPACE_KMSEND
#endif