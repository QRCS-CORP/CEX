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

#ifndef CEX_DUKPTCLIENT_H
#define CEX_DUKPTCLIENT_H

#include "CexDomain.h"

#include "DukptDerivationPurpose.h"
#include "DukptKeyType.h"
#include "DukptKeyUsage.h"
#include "ECB.h"

NAMESPACE_KMS

using Cipher::Block::Mode::ECB;
using Enumeration::DukptDerivationPurpose;
using Enumeration::DukptKeyType;
using Enumeration::DukptKeyUsage;

/// <summary>
/// A C++ implementation of the ANSI X9.24-3 2017 DUKPT.
/// <para>Translated from the official Python implementation: 
/// <see href="https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Python-Source-20180129-1.pdf"/>
/// Test Vectors: <see href="https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Test-Vectors-20180129-1.pdf"/></para>
/// </summary>
class DUKPTClient final
{
private:

    static const uint DUKPT_NUM_REG = 32;
    static const uint DUKPT_MAX_WORK = 16;
    static const size_t AES_BLOCK_SIZE = 16;
    static const size_t HMAC_CODE_SIZE = 32;
    static const size_t DUKPT_MESSAGE_SIZE = 16;

    class DukptClientState;
    std::unique_ptr<DukptClientState> m_clientState;
    std::unique_ptr<Cipher::Block::Mode::ECB> m_ebcMode;

public:

    //~~~Constructor~~~//

    /// <summary>
    /// The DUKPT constructor
    /// </summary>
    DUKPTClient();

    /// <summary>
    /// The DUKPT destructor
    /// </summary>
    ~DUKPTClient();

    //~~~Accessors~~~//

    /// <summary>
    /// The current transaction key register
    /// </summary>
    uint TransactionCounter();

    //~~~Public Functions~~~//

    /// <summary>
    /// Encrypt and authenticate a PIN message.
    /// <para>The PIN is first encrypted, then the cipher-text is used to update a keyed HMAC(SHA2256) function.
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
    /// Encrypt a PIN message
    /// </summary>
    ///
    /// <param name="Message">The PIN message to encrypt</param>
    /// 
    /// <returns>The encrypted message</returns>
    std::vector<byte> Encrypt(const std::vector<byte> &Message);

    /// <summary>
    /// B.6.3 The GenerateWorkingKeys function generates a working key for the current transaction
    /// </summary>
    ///
    /// <param name="WorkingKeyUsage">The derivation key usage</param>
    /// <param name="WorkingKeyType">The cipher key type</param>
    std::vector<byte> GenerateWorkingKeys(DukptKeyUsage WorkingKeyUsage, DukptKeyType WorkingKeyType);

    /// <summary>
    /// B.6.3 Processing Routines; Load an initial key for computing terminal transaction keys in sequence
    /// </summary>
    ///
    /// <param name="InitialKey">The base derivation key</param>
    /// <param name="DeriveKeyType">The cipher key type</param>
    /// <param name="InitialKeyId">The initial key id</param>
    void LoadInitialKey(const std::vector<byte> &InitialKey, DukptKeyType DeriveKeyType, const std::vector<byte> &InitialKeyId);

    /// <summary>
    /// B.6.3 Update Initial Key; Load a new terminal initial key under a pre-existing terminal initial key
    /// </summary>
    ///
    /// <param name="EncryptedInitialKey">The encrypted initial key key</param>
    /// <param name="InitialKeyType">The cipher key type</param>
    /// <param name="NewDeviceId">The new device id</param>
    /// 
    /// <returns>Returns true if initial key loaded successfully</returns>
    bool UpdateInitialKey(const std::vector<byte> &EncryptedInitialKey, DukptKeyType InitialKeyType, const std::vector<byte> &NewDeviceId);

private:

    static uint CountOneBits(uint X);
    static std::vector<byte> CreateDerivationData(DukptDerivationPurpose DerivationPurpose, DukptKeyUsage KeyUsage, DukptKeyType DerivedKeyType, const std::vector<byte> &InitialKeyId, uint Counter);
    std::vector<byte> Decrypt(const std::vector<byte> &Key, const std::vector<byte> &CipherText);
    std::vector<byte> DeriveKey(const std::vector<byte> &DerivationKey, DukptKeyType KeyType, std::vector<byte> &DerivationData);
    std::vector<byte> Encrypt(const std::vector<byte> &Key, const std::vector<byte> &PlainText);
    static uint GetKeyLength(DukptKeyType KeyType);
    static std::vector<byte> IntToBytes(uint X);
    void SetShiftRegister();
    void UpdateDerivationKeys(uint Start, DukptKeyType DeriveKeyType);
    bool UpdateStateForNextTransaction();
};

NAMESPACE_KMSEND
#endif