#include "DUKPTClient.h"
#include "CryptoKmsException.h"
#include "HMAC.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_KMS

using Enumeration::BlockCiphers;
using Mac::HMAC;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Enumeration::SHA2Digests;
using Cipher::SymmetricKey;

class DUKPTClient::DukptClientState
{
public:

    std::vector<std::vector<byte>> FutureKeyRegister;
    std::vector<std::vector<byte>> IntermediateDerivationKeyRegister;
    std::vector<bool> IntermediateDerivationKeyInUse;
    std::vector<byte> DeviceID;
    uint CurrentKey;
    uint ShiftRegister;
    uint TransactionCounter;
    DukptKeyType DerivationKeyType;

    DukptClientState()
        :
        FutureKeyRegister(0),
        IntermediateDerivationKeyRegister(0),
        IntermediateDerivationKeyInUse(0),
        DeviceID(0),
        CurrentKey(0),
        ShiftRegister(0),
        TransactionCounter(0),
        DerivationKeyType(DukptKeyType::None)
    {}

    ~DukptClientState()
    {
        size_t i;

        for (i = 0; i < FutureKeyRegister.size(); ++i)
        {
            IntegerTools::Clear(FutureKeyRegister[i]);
        }

        for (i = 0; i < IntermediateDerivationKeyRegister.size(); ++i)
        {
            IntegerTools::Clear(IntermediateDerivationKeyRegister[i]);
        }

        IntegerTools::Clear(DeviceID);
        IntermediateDerivationKeyInUse.clear();
        CurrentKey = 0;
        ShiftRegister = 0;
        TransactionCounter = 0;
        DerivationKeyType = DukptKeyType::None;
    }
};

//~~~Constructor~~~//

DUKPTClient::DUKPTClient()
    :
    m_clientState(new DukptClientState), 
    m_ebcMode(new ECB(BlockCiphers::AES)) 
{
}

DUKPTClient::~DUKPTClient()
{
    if (m_ebcMode != nullptr)
    {
        m_ebcMode.reset(nullptr);
    }

    if (m_clientState != nullptr)
    {
        m_clientState.reset(nullptr);
    }
}

//~~~Accessors~~~//

uint DUKPTClient::TransactionCounter()
{
    return m_clientState->TransactionCounter;
}

//~~~Public Functions~~~//

std::vector<byte> DUKPTClient::Encrypt(const std::vector<byte> &Message)
{
    std::vector<byte> ctxt;
    std::vector<byte> wkey;

    wkey = GenerateWorkingKeys(DukptKeyUsage::PINEncryption, m_clientState->DerivationKeyType);
    ctxt = Encrypt(wkey, Message);

    return ctxt;
}

std::vector<byte> DUKPTClient::EncryptAuthenticate(const std::vector<byte> &Message, const std::vector<byte> &AdditionalData)
{
    std::vector<byte> acpt(DUKPT_MESSAGE_SIZE + HMAC_CODE_SIZE);
    std::vector<byte> ctxt;
    std::vector<byte> hkey;

    ctxt = Encrypt(Message);
    MemoryTools::Copy(ctxt, 0, acpt, 0, ctxt.size());

    hkey = GenerateWorkingKeys(DukptKeyUsage::MessageAuthenticationBothWays, m_clientState->DerivationKeyType);
    SymmetricKey kp(hkey);
    HMAC gen(SHA2Digests::SHA2256);
    gen.Initialize(kp);

    if (AdditionalData.size() != 0)
    {
        gen.Update(AdditionalData, 0, AdditionalData.size());
    }

    gen.Update(ctxt, 0, ctxt.size());
    gen.Finalize(acpt, ctxt.size());

    return acpt;
}

void DUKPTClient::LoadInitialKey(const std::vector<byte> &InitialKey, DukptKeyType DeriveKeyType, const std::vector<byte> &InitialKeyId)
{
    m_clientState->IntermediateDerivationKeyRegister.resize(DUKPT_NUM_REG, std::vector<byte>(0));
    m_clientState->IntermediateDerivationKeyInUse.resize(DUKPT_NUM_REG, false);
    m_clientState->FutureKeyRegister.resize(DUKPT_NUM_REG, std::vector<byte>(0));
    m_clientState->IntermediateDerivationKeyRegister[0] = InitialKey;
    m_clientState->IntermediateDerivationKeyInUse[0] = true;
    m_clientState->DeviceID = InitialKeyId;
    m_clientState->TransactionCounter = 0;
    m_clientState->ShiftRegister = 1;
    m_clientState->CurrentKey = 0;
    m_clientState->DerivationKeyType = DeriveKeyType;

    UpdateDerivationKeys(DUKPT_NUM_REG - 1, DeriveKeyType);
    m_clientState->TransactionCounter += 1;
}

bool DUKPTClient::UpdateInitialKey(const std::vector<byte> &EncryptedInitialKey, DukptKeyType InitialKeyType, const std::vector<byte> &NewDeviceId)
{
    std::vector<byte> tmpk1(AES_BLOCK_SIZE);
    std::vector<byte> tmpk2(AES_BLOCK_SIZE);
    std::vector<byte> data;
    std::vector<byte> ekey;
    std::vector<byte> nkey;
    size_t i;
    uint n;
    bool ret;

    ret = true;

    if (m_clientState->TransactionCounter > ((1ULL << DUKPT_NUM_REG) - 1))
    {
        ret = false;
    }

    if (ret == true)
    {
        data = CreateDerivationData(DukptDerivationPurpose::DerivationOrWorkingKey, DukptKeyUsage::KeyEncryptionKey, InitialKeyType, m_clientState->DeviceID, m_clientState->TransactionCounter);
        ekey = DeriveKey(m_clientState->FutureKeyRegister[m_clientState->CurrentKey], InitialKeyType, data);
        n = (GetKeyLength(InitialKeyType) + 127);

        for (i = 1; i < n; ++i)
        {
            MemoryTools::Copy(EncryptedInitialKey, (i - 1) * AES_BLOCK_SIZE, tmpk1, 0, AES_BLOCK_SIZE);
            tmpk2 = Decrypt(ekey, tmpk1);
            MemoryTools::Copy(tmpk2, 0, nkey, (i - 1) * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        }

        LoadInitialKey(nkey, InitialKeyType, NewDeviceId);
    }

    return ret;
}

//~~~Private Functions~~~//

uint DUKPTClient::CountOneBits(uint X)
{
    uint bits;
    uint mask;

    bits = 0;
    mask = 1ULL << (DUKPT_NUM_REG - 1);

    while (mask > 0)
    {
        if (X & mask)
        {
            bits += 1;
        }

        mask >>= 1;
    }

    return bits;
}

std::vector<byte> DUKPTClient::CreateDerivationData(DukptDerivationPurpose DerivationPurpose, DukptKeyUsage KeyUsage,
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

std::vector<byte> DUKPTClient::Decrypt(const std::vector<byte> &Key, const std::vector<byte> &CipherText)
{
    std::vector<byte> res(AES_BLOCK_SIZE);

    SymmetricKey kp(Key);
    m_ebcMode->Initialize(false, kp);
    m_ebcMode->DecryptBlock(CipherText, res);

    return res;
}

std::vector<byte> DUKPTClient::DeriveKey(const std::vector<byte> &DerivationKey, DukptKeyType KeyType, std::vector<byte> &DerivationData)
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

std::vector<byte> DUKPTClient::Encrypt(const std::vector<byte> &Key, const std::vector<byte> &PlainText)
{
    std::vector<byte> res(AES_BLOCK_SIZE);

    SymmetricKey kp(Key);
    m_ebcMode->Initialize(true, kp);
    m_ebcMode->EncryptBlock(PlainText, res);

    return res;
}

std::vector<byte> DUKPTClient::GenerateWorkingKeys(DukptKeyUsage WorkingKeyUsage, DukptKeyType WorkingKeyType)
{
    std::vector<byte> wkey(AES_BLOCK_SIZE);
    std::vector<byte> data;
    bool val;

    val = true;
    SetShiftRegister();

    while (m_clientState->IntermediateDerivationKeyInUse[m_clientState->CurrentKey] == false)
    {
        m_clientState->TransactionCounter += m_clientState->ShiftRegister;

        if (m_clientState->TransactionCounter > ((1ULL << DUKPT_NUM_REG) - 1))
        {
            val = false;
            break;
        }

        SetShiftRegister();
    }

    if (val == true)
    {
        data = CreateDerivationData(DukptDerivationPurpose::DerivationOrWorkingKey, WorkingKeyUsage, WorkingKeyType, m_clientState->DeviceID, m_clientState->TransactionCounter);
        wkey = DeriveKey(m_clientState->IntermediateDerivationKeyRegister[m_clientState->CurrentKey], WorkingKeyType, data);
        UpdateStateForNextTransaction();
    }

    return wkey;
}

uint DUKPTClient::GetKeyLength(DukptKeyType KeyType)
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

std::vector<byte> DUKPTClient::IntToBytes(uint X)
{
    std::vector<byte> ret(4);

    ret[3] = static_cast<byte>(X);
    ret[2] = static_cast<byte>(X >> 8);
    ret[1] = static_cast<byte>(X >> 16);
    ret[0] = static_cast<byte>(X >> 24);

    return ret;
}

void DUKPTClient::UpdateDerivationKeys(uint Start, DukptKeyType DeriveKeyType)
{
    std::vector<byte> bkey;
    std::vector<byte> data;
    uint i;
    uint j;

    i = Start;
    j = 1UL << Start;
    bkey = m_clientState->IntermediateDerivationKeyRegister[m_clientState->CurrentKey];

    while (j != 0)
    {
        data = CreateDerivationData(DukptDerivationPurpose::DerivationOrWorkingKey, DukptKeyUsage::KeyDerivation, DeriveKeyType, m_clientState->DeviceID, m_clientState->TransactionCounter | j);
        m_clientState->IntermediateDerivationKeyRegister[i] = DeriveKey(bkey, DeriveKeyType, data);
        m_clientState->IntermediateDerivationKeyInUse[i] = true;
        j = j >> 1;
        i = i - 1;
    }
}

bool DUKPTClient::UpdateStateForNextTransaction()
{
    uint onebits;
    bool ret;

    ret = true;
    onebits = CountOneBits(m_clientState->TransactionCounter);

    if (onebits <= DUKPT_MAX_WORK)
    {
        const size_t KEYLEN = (m_clientState->DerivationKeyType == DukptKeyType::AES128) ? AES_BLOCK_SIZE : 2 * AES_BLOCK_SIZE;
        UpdateDerivationKeys(m_clientState->CurrentKey, m_clientState->DerivationKeyType);
        m_clientState->IntermediateDerivationKeyRegister[m_clientState->CurrentKey] = std::vector<byte>(KEYLEN, 0x00);
        m_clientState->IntermediateDerivationKeyInUse[m_clientState->CurrentKey] = false;
        m_clientState->TransactionCounter += 1;
    }
    else
    {
        IntegerTools::Clear(m_clientState->IntermediateDerivationKeyRegister[m_clientState->CurrentKey]);
        m_clientState->IntermediateDerivationKeyInUse[m_clientState->CurrentKey] = false;
        m_clientState->TransactionCounter += m_clientState->ShiftRegister;
    }

    if (m_clientState->TransactionCounter > (1ULL << DUKPT_NUM_REG) - 1)
    {
        ret = false;
    }

    return ret;
}

void DUKPTClient::SetShiftRegister()
{
    m_clientState->ShiftRegister = 1;
    m_clientState->CurrentKey = 0;

    if (m_clientState->TransactionCounter != 0)
    {
        while ((m_clientState->ShiftRegister & m_clientState->TransactionCounter) == 0)
        {
            m_clientState->ShiftRegister <<= 1;
            m_clientState->CurrentKey += 1;
        }
    }
}

NAMESPACE_KMSEND