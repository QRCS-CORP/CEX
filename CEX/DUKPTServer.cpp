#include "DUKPTServer.h"
#include "CryptoKmsException.h"
#include "HMAC.h"
#include "MemoryTools.h"

NAMESPACE_KMS

using Enumeration::BlockCiphers;
using Mac::HMAC;
using Tools::MemoryTools;
using Enumeration::SHA2Digests;
using Cipher::SymmetricKey;

//~~~Constructor~~~//

DUKPTServer::DUKPTServer()
    :
    m_ebcMode(new ECB(BlockCiphers::AES)) 
{
}

DUKPTServer::~DUKPTServer()
{
    if (m_ebcMode != nullptr)
    {
        m_ebcMode.reset(nullptr);
    }
}

//~~~Public Functions~~~//

std::vector<byte> DUKPTServer::Decrypt(const std::vector<byte> &Bdk, const std::vector<byte> &KeyId, const std::vector<byte> &CipherText)
{
    if (CipherText.size() != DUKPT_PIN_SIZE)
    {
        throw CryptoKmsException(std::string("DecryptPin"), std::string("DUKPTServer"), std::string("The ciphertext is invalid!"), ErrorCodes::InvalidSize);
    }

    const DukptKeyType KEYTYPE = (Bdk.size() == 16 ? DukptKeyType::AES128 : Bdk.size() == 24 ? DukptKeyType::AES192 : DukptKeyType::AES256);
    std::vector<byte> id(8);
    std::vector<byte> ptxt(AES_BLOCK_SIZE);
    DukptServerState state;
    uint ctr;

    MemoryTools::Copy(KeyId, 0, id, 0, id.size());
    ctr = IntegerTools::BeBytesTo32(KeyId, 8);
    DeriveWorkingKey(state, Bdk, DukptKeyUsage::PINEncryption, KEYTYPE, id, ctr);
    ptxt = Decrypt(state.WorkingKey, CipherText);

    return ptxt;
}

std::vector<byte> DUKPTServer::DecryptVerify(const std::vector<byte> &Bdk, const std::vector<byte> &KeyId, const std::vector<byte> &CipherText, const std::vector<byte> &AdditionalData)
{
    const DukptKeyType KEYTYPE = (Bdk.size() == 16 ? DukptKeyType::AES128 : Bdk.size() == 24 ? DukptKeyType::AES192 : DukptKeyType::AES256);
    std::vector<byte> code(HMAC_CODE_SIZE);
    std::vector<byte> ctxt(DUKPT_PIN_SIZE);
    std::vector<byte> id(8);
    std::vector<byte> ptxt(DUKPT_PIN_SIZE, 0x00);
    std::vector<byte> tmpc(32);
    DukptServerState state;
    uint ctr;

    if (CipherText.size() != (HMAC_CODE_SIZE + DUKPT_PIN_SIZE))
    {
        throw CryptoKmsException(std::string("VerifyDecryptPin"), std::string("DUKPTServer"), std::string("The ciphertext is invalid!"), ErrorCodes::InvalidSize);
    }

    MemoryTools::Copy(KeyId, 0, id, 0, id.size());
    ctr = IntegerTools::BeBytesTo32(KeyId, 8);
    DeriveWorkingKey(state, Bdk, DukptKeyUsage::MessageAuthenticationBothWays, KEYTYPE, id, ctr + 1);

    SymmetricKey kp(state.WorkingKey);
    HMAC gen(SHA2Digests::SHA2256);
    gen.Initialize(kp);

    if (AdditionalData.size() != 0)
    {
        gen.Update(AdditionalData, 0, AdditionalData.size());
    }

    gen.Update(CipherText, 0, DUKPT_PIN_SIZE);
    gen.Finalize(tmpc, 0);

    MemoryTools::Copy(CipherText, DUKPT_PIN_SIZE, code, 0, code.size());

    if (IntegerTools::Verify(tmpc, code, tmpc.size()) != 0)
    {
        throw CryptoAuthenticationFailure(std::string("VerifyDecryptPin"), std::string("DUKPTServer"), std::string("The ciphertext failed authentication!"), ErrorCodes::AuthenticationFailure);
    }

    MemoryTools::Copy(CipherText, 0, ctxt, 0, ctxt.size());
    ptxt = Decrypt(Bdk, KeyId, ctxt);

    return ptxt;
}

//~~~Private Functions~~~//

std::vector<byte> DUKPTServer::CreateDerivationData(DukptDerivationPurpose DerivationPurpose, DukptKeyUsage KeyUsage,
    DukptKeyType DerivedKeyType, const std::vector<byte> &InitialKeyId, uint Counter)
{
    std::vector<byte> data(AES_BLOCK_SIZE);
    data[0] = 1;
    data[1] = 1;

    if (KeyUsage == DukptKeyUsage::KeyEncryptionKey)
    {
        data[2] = 0;
        data[3] = 2;
    }
    else if (KeyUsage == DukptKeyUsage::PINEncryption)
    {
        data[2] = 16;
        data[3] = 0;
    }
    else if (KeyUsage == DukptKeyUsage::MessageAuthenticationGeneration)
    {
        data[2] = 32;
        data[3] = 0;
    }
    else if (KeyUsage == DukptKeyUsage::MessageAuthenticationVerification)
    {
        data[2] = 32;
        data[3] = 1;
    }
    else if (KeyUsage == DukptKeyUsage::MessageAuthenticationBothWays)
    {
        data[2] = 32;
        data[3] = 2;
    }
    else if (KeyUsage == DukptKeyUsage::DataEncryptionEncrypt)
    {
        data[2] = 48;
        data[3] = 0;
    }
    else if (KeyUsage == DukptKeyUsage::DataEncryptionDecrypt)
    {
        data[2] = 48;
        data[3] = 1;
    }
    else if (KeyUsage == DukptKeyUsage::DataEncryptionBothWays)
    {
        data[2] = 48;
        data[3] = 2;
    }
    else if (KeyUsage == DukptKeyUsage::KeyDerivation)
    {
        data[2] = 128;
        data[3] = 0;
    }
    else
    {
        data[2] = 128;
        data[3] = 1;
    }

    if (DerivedKeyType == DukptKeyType::AES128)
    {
        data[4] = 0;
        data[5] = 2;
    }
    else if (DerivedKeyType == DukptKeyType::AES192)
    {
        data[4] = 0;
        data[5] = 3;
    }
    else
    {
        data[4] = 0;
        data[5] = 4;
    }

    if (DerivedKeyType == DukptKeyType::AES128)
    {
        data[6] = 0;
        data[7] = 128;
    }
    else if (DerivedKeyType == DukptKeyType::AES192)
    {
        data[6] = 0;
        data[7] = 192;
    }
    else
    {
        data[6] = 1;
        data[7] = 0;
    }

    if (DerivationPurpose == DukptDerivationPurpose::InitialKey)
    {
        data[8] = InitialKeyId[0];
        data[9] = InitialKeyId[1];
        data[10] = InitialKeyId[2];
        data[11] = InitialKeyId[3];
        data[12] = InitialKeyId[4];
        data[13] = InitialKeyId[5];
        data[14] = InitialKeyId[6];
        data[15] = InitialKeyId[7];
    }
    else
    {
        data[8] = InitialKeyId[4];
        data[9] = InitialKeyId[5];
        data[10] = InitialKeyId[6];
        data[11] = InitialKeyId[7];

        std::vector<byte> tmp = IntToBytes(Counter);
        data[12] = tmp[0];
        data[13] = tmp[1];
        data[14] = tmp[2];
        data[15] = tmp[3];
    }

    return data;
}

std::vector<byte> DUKPTServer::Decrypt(const std::vector<byte> &Key, const std::vector<byte> &CipherText)
{
    std::vector<byte> ptxt(AES_BLOCK_SIZE);

    SymmetricKey kp(Key);
    m_ebcMode->Initialize(false, kp);
    m_ebcMode->DecryptBlock(CipherText, ptxt);

    return ptxt;
}

std::vector<byte> DUKPTServer::DeriveInitialKey(const std::vector<byte> &Bdk, DukptKeyType KeyType, const std::vector<byte> &InitialKeyId)
{
    std::vector<byte> ikey(AES_BLOCK_SIZE);
    std::vector<byte> data(AES_BLOCK_SIZE);

    data = CreateDerivationData(DukptDerivationPurpose::InitialKey, DukptKeyUsage::KeyDerivationInitialKey, KeyType, InitialKeyId, 0);
    ikey = DeriveKey(Bdk, KeyType, data);

    return ikey;
}

std::vector<byte> DUKPTServer::DeriveKey(const std::vector<byte> &DerivationKey, DukptKeyType KeyType, std::vector<byte> &DerivationData)
{
    std::vector<byte> rkey;
    std::vector<byte> tmpk(AES_BLOCK_SIZE);
    uint i;
    uint L;
    uint n;

    L = GetKeyLength(KeyType);
    n = (L / 128);
    rkey.resize(n * AES_BLOCK_SIZE);

    for (i = 1; i < n + 1; ++i)
    {
        DerivationData[1] = i;
        tmpk = Encrypt(DerivationKey, DerivationData);
        MemoryTools::Copy(tmpk, 0, rkey, (i - 1) * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    }

    return rkey;
}

void DUKPTServer::DeriveWorkingKey(DukptServerState &State, const std::vector<byte> &Bdk, DukptKeyUsage WorkingKeyUsage, DukptKeyType WorkingKeyType, const std::vector<byte> &InitialKeyId, uint Counter)
{
    uint mask;
    uint wctr;

    mask = 0x80000000UL;
    wctr = 0;
    State.DerivationKey = DeriveInitialKey(Bdk, WorkingKeyType, InitialKeyId);

    while (mask > 0)
    {
        if ((mask & Counter) != 0)
        {
            // performance degrades as transaction counter increases,
            // re-key count is amplified by the counter position:
            // set size:  10  21   32   100  1000  10000   100000
            // re-keys required @ counter position
            // key count: 3@7 4@15 5@31 6@63 9@511 13@8191 16@65535
            // AES-256 requires 2x this number, 2 for each key generation.
            // Worst case is near upper limit of 500k keys (max work factor is 16)
            // Using AES-256 doubles the re-keys for the longer key,
            // add the 2 initial and 2 final re-keys, that is 36 AES-256 re-keys..
            wctr = wctr | mask;
            State.DerivationData = CreateDerivationData(DukptDerivationPurpose::DerivationOrWorkingKey, DukptKeyUsage::KeyDerivation, WorkingKeyType, InitialKeyId, wctr);
            State.DerivationKey = DeriveKey(State.DerivationKey, WorkingKeyType, State.DerivationData);
        }

        mask >>= 1;
    }

    State.DerivationData = CreateDerivationData(DukptDerivationPurpose::DerivationOrWorkingKey, WorkingKeyUsage, WorkingKeyType, InitialKeyId, Counter);
    State.WorkingKey = DeriveKey(State.DerivationKey, WorkingKeyType, State.DerivationData);
}

std::vector<byte> DUKPTServer::Encrypt(const std::vector<byte> &Key, const std::vector<byte> &PlainText)
{
    std::vector<byte> ctxt(AES_BLOCK_SIZE);

    SymmetricKey kp(Key);
    m_ebcMode->Initialize(true, kp);
    m_ebcMode->EncryptBlock(PlainText, ctxt);

    return ctxt;
}

std::vector<byte> DUKPTServer::IntToBytes(uint X)
{
    std::vector<byte> ret(4);

    ret[3] = static_cast<byte>(X);
    ret[2] = static_cast<byte>(X >> 8);
    ret[1] = static_cast<byte>(X >> 16);
    ret[0] = static_cast<byte>(X >> 24);

    return ret;
}

uint DUKPTServer::GetKeyLength(DukptKeyType KeyType)
{
    uint keylen;

    if (KeyType == DukptKeyType::AES128)
    {
        keylen = 128;
    }
    else if (KeyType == DukptKeyType::AES192)
    {
        keylen = 192;
    }
    else
    {
        keylen = 256;
    }

    return keylen;
}

NAMESPACE_KMSEND