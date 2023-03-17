#include "KyberBase.h"

NAMESPACE_KYBER

const std::vector<uint16_t> KyberBase::Zetas =
{
    0xFBEC, 0xFD0A, 0xFE99, 0xFA13, 0x05D5, 0x058E, 0x011F, 0x00CA,
    0xFF55, 0x026E, 0x0629, 0x00B6, 0x03C2, 0xFB4E, 0xFA3E, 0x05BC,
    0x023D, 0xFAD3, 0x0108, 0x017F, 0xFCC3, 0x05B2, 0xF9BE, 0xFF7E,
    0xFD57, 0x03F9, 0x02DC, 0x0260, 0xF9FA, 0x019B, 0xFF33, 0xF9DD,
    0x04C7, 0x028C, 0xFDD8, 0x03F7, 0xFAF3, 0x05D3, 0xFEE6, 0xF9F8,
    0x0204, 0xFFF8, 0xFEC0, 0xFD66, 0xF9AE, 0xFB76, 0x007E, 0x05BD,
    0xFCAB, 0xFFA6, 0xFEF1, 0x033E, 0x006B, 0xFA73, 0xFF09, 0xFC49,
    0xFE72, 0x03C1, 0xFA1C, 0xFD2B, 0x01C0, 0xFBD7, 0x02A5, 0xFB05,
    0xFBB1, 0x01AE, 0x022B, 0x034B, 0xFB1D, 0x0367, 0x060E, 0x0069,
    0x01A6, 0x024B, 0x00B1, 0xFF15, 0xFEDD, 0xFE34, 0x0626, 0x0675,
    0xFF0A, 0x030A, 0x0487, 0xFF6D, 0xFCF7, 0x05CB, 0xFDA6, 0x045F,
    0xF9CA, 0x0284, 0xFC98, 0x015D, 0x01A2, 0x0149, 0xFF64, 0xFFB5,
    0x0331, 0x0449, 0x025B, 0x0262, 0x052A, 0xFAFB, 0xFA47, 0x0180,
    0xFB41, 0xFF78, 0x04C2, 0xFAC9, 0xFC96, 0x00DC, 0xFB5D, 0xF985,
    0xFB5F, 0xFA06, 0xFB02, 0x031A, 0xFA1A, 0xFCAA, 0xFC9A, 0x01DE,
    0xFF94, 0xFECC, 0x03E4, 0x03DF, 0x03BE, 0xFA4C, 0x05F2, 0x065C
};

// reduce.c

int16_t KyberBase::MontgomeryReduce(int32_t A)
{
    int32_t t;
    int16_t u;

    u = static_cast<int16_t>(A * static_cast<int64_t>(KYBER_QINV));
    t = (int32_t)u * KYBER_Q;
    t = A - t;
    t >>= 16;

    return static_cast<int16_t>(t);
}

int16_t KyberBase::BarrettReduce(int16_t A)
{
    int16_t t;
    const int16_t V = ((1U << 26) + KYBER_Q / 2) / KYBER_Q;

    t = (static_cast<int32_t>(V) * A + (1 << 25)) >> 26;
    t *= KYBER_Q;

    return (A - t);
}

// ntt.c

int16_t KyberBase::FqMul(int16_t A, int16_t B)
{
    return MontgomeryReduce(static_cast<int32_t>(A) * B);
}

void KyberBase::Ntt(Poly &R)
{
    size_t j;
    size_t k;
    int16_t t;
    int16_t zeta;

    k = 1;

    for (size_t len = 128; len >= 2; len >>= 1)
    {
        for (size_t start = 0; start < R.coeffs.size(); start = (j + len))
        {
            zeta = static_cast<int16_t>(Zetas[k]);
            ++k;

            for (j = start; j < start + len; ++j)
            {
                t = FqMul(zeta, R.coeffs[j + len]);
                R.coeffs[j + len] = R.coeffs[j] - t;
                R.coeffs[j] = R.coeffs[j] + t;
            }
        }
    }
}

void KyberBase::InvNtt(Poly &R)
{
    size_t j;
    size_t k;
    int16_t t;
    int16_t zeta;
    const int16_t F = 1441;

    k = 127;

    for (size_t len = 2; len <= 128; len <<= 1)
    {
        for (size_t start = 0; start < R.coeffs.size(); start = j + len)
        {
            zeta = static_cast<int16_t>(Zetas[k]);
            --k;

            for (j = start; j < start + len; ++j)
            {
                t = R.coeffs[j];
                R.coeffs[j] = BarrettReduce(t + R.coeffs[j + len]);
                R.coeffs[j + len] = R.coeffs[j + len] - t;
                R.coeffs[j + len] = FqMul(zeta, R.coeffs[j + len]);
            }
        }
    }

    for (j = 0; j < R.coeffs.size(); ++j)
    {
        R.coeffs[j] = FqMul(R.coeffs[j], F);
    }
}

void KyberBase::BaseMul(int16_t R[2], const int16_t A[2], const int16_t B[2], int16_t Zeta)
{
    R[0] = FqMul(A[1], B[1]);
    R[0] = FqMul(R[0], Zeta);
    R[0] += FqMul(A[0], B[0]);
    R[1] = FqMul(A[0], B[1]);
    R[1] += FqMul(A[1], B[0]);
}

// poly.c

void KyberBase::PolyCbdEta1(Poly &R, const std::vector<uint8_t> &Buf, uint32_t Eta1)
{
    if (Eta1 == 2)
    {
        Cbd2(R, Buf);
    }
    else
    {
        Cbd3(R, Buf);
    }
}

void KyberBase::PolyCbdEta2(Poly &R, const std::vector<uint8_t> &Buf)
{
    Cbd2(R, Buf);
}

void KyberBase::PolyToBytes(std::vector<uint8_t> &R, size_t ROffset, const Poly &A)
{
    uint16_t t0;
    uint16_t t1;

    for (size_t i = 0; i < A.coeffs.size() / 2; ++i)
    {
        // map to positive standard representatives
        t0 = A.coeffs[2 * i];
        t0 += (static_cast<int16_t>(t0) >> 15) & KYBER_Q;
        t1 = A.coeffs[(2 * i) + 1];
        t1 += (static_cast<int16_t>(t1) >> 15) & KYBER_Q;
        R[ROffset + (3 * i)] = static_cast<uint8_t>(t0 >> 0);
        R[ROffset + (3 * i) + 1] = static_cast<uint8_t>((t0 >> 8) | (t1 << 4));
        R[ROffset + (3 * i) + 2] = static_cast<uint8_t>(t1 >> 4);
    }
}

void KyberBase::PolyFromBytes(Poly &R, const std::vector<uint8_t> &A, size_t AOffset)
{
    for (size_t i = 0; i < R.coeffs.size() / 2; ++i)
    {
        R.coeffs[(2 * i)] = (((A[AOffset + (3 * i)] >> 0) | (static_cast<uint16_t>(A[AOffset + (3 * i) + 1]) << 8)) & 0x0FFF);
        R.coeffs[(2 * i) + 1] = (((A[AOffset + (3 * i) + 1] >> 4) | (static_cast<uint16_t>(A[AOffset + (3 * i) + 2]) << 4)) & 0x0FFF);
    }
}

void KyberBase::PolyToMsg(std::vector<uint8_t> &Msg, const Poly &A)
{
    uint16_t t;

    for (size_t i = 0; i < A.coeffs.size() / 8; ++i)
    {
        Msg[i] = 0;

        for (size_t j = 0; j < 8; ++j)
        {
            t = A.coeffs[(8 * i) + j];
            t += (static_cast<int16_t>(t) >> 15) & KYBER_Q;
            t = (((t << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
            Msg[i] |= static_cast<uint8_t>(t << j);
        }
    }
}

void KyberBase::PolyGetNoiseEta1(Poly &R, const std::vector<uint8_t> &Seed, size_t SOffset, uint8_t Nonce, uint32_t Eta1)
{
    std::vector<uint8_t> buf(Eta1 * KYBER_N / 4);
    std::vector<uint8_t> extkey(KYBER_SYMBYTES + 1);

    MemoryTools::Copy(Seed, SOffset, extkey, 0, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = Nonce;
    Keccak::XOFP1600(extkey, 0, extkey.size(), buf, 0, buf.size(), Keccak::KECCAK256_RATE_SIZE);

    PolyCbdEta1(R, buf, Eta1);
}

void KyberBase::PolyGetNoiseEta2(Poly &R, const std::vector<uint8_t> &Seed, size_t SOffset, uint8_t Nonce)
{
    std::vector<uint8_t> buf(KYBER_ETA2 * KYBER_N / 4);
    std::vector<uint8_t> extkey(KYBER_SYMBYTES + 1);

    MemoryTools::Copy(Seed, SOffset, extkey, 0, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = Nonce;
    Keccak::XOFP1600(extkey, 0, extkey.size(), buf, 0, buf.size(), Keccak::KECCAK256_RATE_SIZE);
    PolyCbdEta2(R, buf);
}

void KyberBase::PolyReduce(Poly &R)
{
    for (size_t i = 0; i < R.coeffs.size(); ++i)
    {
        R.coeffs[i] = BarrettReduce(R.coeffs[i]);
    }
}

void KyberBase::PolyNttv2(Poly &R)
{
    Ntt(R);
    PolyReduce(R);
}

void KyberBase::PolyInvNttToMontgomery(Poly &R)
{
    InvNtt(R);
}

void KyberBase::PolyBaseMulMontgomery(Poly &R, const Poly &A, const Poly &B)
{
    for (size_t i = 0; i < R.coeffs.size() / 4; ++i)
    {
        BaseMul(R.coeffs.data() + (4 * i), A.coeffs.data() + (4 * i), B.coeffs.data() + (4 * i), static_cast<int16_t>(Zetas[64 + i]));
        BaseMul(R.coeffs.data() + (4 * i) + 2, A.coeffs.data() + (4 * i) + 2, B.coeffs.data() + (4 * i) + 2, -static_cast<int16_t>(Zetas[64 + i]));
    }
}

void KyberBase::PolyToMont(Poly &R)
{
    const int16_t F = (1ULL << 32) % KYBER_Q;

    for (size_t i = 0; i < R.coeffs.size(); ++i)
    {
        R.coeffs[i] = MontgomeryReduce(static_cast<int32_t>(R.coeffs[i]) * F);
    }
}

// polyvec.c

void KyberBase::PolyVecCompress(std::vector<uint8_t> &R, const PolyVec &A)
{
    size_t idx;

    if (A.vec.size() == 4 || A.vec.size() == 5)
    {
        std::array<uint16_t, 8> t;

        idx = 0;

        for (size_t i = 0; i < A.vec.size(); ++i)
        {
            for (size_t j = 0; j < KYBER_N / 8; ++j)
            {
                for (size_t k = 0; k < 8; ++k)
                {
                    t[k] = static_cast<uint16_t>(A.vec[i].coeffs[(8 * j) + k]);
                    t[k] += static_cast<uint16_t>((static_cast<int16_t>(t[k]) >> 15) & KYBER_Q);
                    t[k] = static_cast<uint16_t>((((static_cast<uint32_t>(t[k]) << 11) + KYBER_Q / 2) / KYBER_Q) & 0x07FF);
                }

                R[idx] = static_cast<uint8_t>(t[0] >> 0);
                R[idx + 1] = static_cast<uint8_t>((t[0] >> 8) | (t[1] << 3));
                R[idx + 2] = static_cast<uint8_t>((t[1] >> 5) | (t[2] << 6));
                R[idx + 3] = static_cast<uint8_t>(t[2] >> 2);
                R[idx + 4] = static_cast<uint8_t>((t[2] >> 10) | (t[3] << 1));
                R[idx + 5] = static_cast<uint8_t>((t[3] >> 7) | (t[4] << 4));
                R[idx + 6] = static_cast<uint8_t>((t[4] >> 4) | (t[5] << 7));
                R[idx + 7] = static_cast<uint8_t>(t[5] >> 1);
                R[idx + 8] = static_cast<uint8_t>((t[5] >> 9) | (t[6] << 2));
                R[idx + 9] = static_cast<uint8_t>((t[6] >> 6) | (t[7] << 5));
                R[idx + 10] = static_cast<uint8_t>(t[7] >> 3);
                idx += 11;
            }
        }
    }
    else if (A.vec.size() == 2 || A.vec.size() == 3)
    {
        std::array<uint16_t, 4> t;

        idx = 0;

        for (size_t i = 0; i < A.vec.size(); ++i)
        {
            for (size_t j = 0; j < KYBER_N / 4; ++j)
            {
                for (size_t k = 0; k < 4; ++k)
                {
                    t[k] = static_cast<uint16_t>(A.vec[i].coeffs[(4 * j) + k]);
                    t[k] += static_cast<uint16_t>((static_cast<int16_t>(t[k]) >> 15) & KYBER_Q);
                    t[k] = static_cast<uint16_t>((((static_cast<uint32_t>(t[k]) << 10) + KYBER_Q / 2) / KYBER_Q) & 0x03FF);
                }

                R[idx] = static_cast<uint8_t>(t[0] >> 0);
                R[idx + 1] = static_cast<uint8_t>((t[0] >> 8) | (t[1] << 2));
                R[idx + 2] = static_cast<uint8_t>((t[1] >> 6) | (t[2] << 4));
                R[idx + 3] = static_cast<uint8_t>((t[2] >> 4) | (t[3] << 6));
                R[idx + 4] = static_cast<uint8_t>(t[3] >> 2);
                idx += 5;
            }
        }
    }
}

void KyberBase::PolyVecToBytes(std::vector<uint8_t> &R, const PolyVec &A)
{
    for (size_t i = 0; i < A.vec.size(); ++i)
    {
        PolyToBytes(R, (i * KYBER_POLYBYTES), A.vec[i]);
    }
}

void KyberBase::PolyVecFromBytes(PolyVec &R, const std::vector<uint8_t> &A)
{
    for (size_t i = 0; i < R.vec.size(); ++i)
    {
        PolyFromBytes(R.vec[i], A, i * KYBER_POLYBYTES);
    }
}

void KyberBase::PolyVecNtt(PolyVec &R)
{
    for (size_t i = 0; i < R.vec.size(); ++i)
    {
        PolyNttv2(R.vec[i]);
    }
}

void KyberBase::PolyVecInvNttToMont(PolyVec &R)
{
    for (size_t i = 0; i < R.vec.size(); ++i)
    {
        PolyInvNttToMontgomery(R.vec[i]);
    }
}

void KyberBase::PolyVecBaseMulAccMontgomery(Poly &R, const PolyVec &A, const PolyVec &B)
{
    Poly t;

    PolyBaseMulMontgomery(R, A.vec[0], B.vec[0]);

    for (size_t i = 1; i < A.vec.size(); ++i)
    {
        PolyBaseMulMontgomery(t, A.vec[i], B.vec[i]);
        PolyAdd(R, R, t);
    }

    PolyReduce(R);
}

void KyberBase::PolyVecReduce(PolyVec &R)
{
    for (size_t i = 0; i < R.vec.size(); ++i)
    {
        PolyReduce(R.vec[i]);
    }
}

void KyberBase::PolyVecAdd(PolyVec &R, const PolyVec &A, const PolyVec &B)
{
    for (size_t i = 0; i < R.vec.size(); ++i)
    {
        PolyAdd(R.vec[i], A.vec[i], B.vec[i]);
    }
}

// indcpa.c

void KyberBase::PackPk(std::vector<uint8_t> &R, const PolyVec &Pk, const std::vector<uint8_t> &Seed)
{
    PolyVecToBytes(R, Pk);
    MemoryTools::Copy(Seed, 0, R, Pk.vec.size() * KYBER_POLYBYTES, KYBER_SYMBYTES);
}

void KyberBase::UnPackPk(PolyVec &Pk, std::vector<uint8_t> &Seed, const std::vector<uint8_t> &PackedPk)
{
    PolyVecFromBytes(Pk, PackedPk);
    MemoryTools::Copy(PackedPk, Pk.vec.size() * KYBER_POLYBYTES, Seed, 0, KYBER_SYMBYTES);
}

void KyberBase::PackSk(std::vector<uint8_t> &R, const PolyVec &Sk)
{
    PolyVecToBytes(R, Sk);
}

void KyberBase::UnPackSk(PolyVec &Sk, const std::vector<uint8_t> &PackedSk)
{
    PolyVecFromBytes(Sk, PackedSk);
}

void KyberBase::PackCiphertext(std::vector<uint8_t> &R, const PolyVec &B, const Poly &V, uint32_t K)
{
    const size_t ROFT = (K > 3 ? 352 : 320) * K;

    PolyVecCompress(R, B);

#if defined(CEX_HAS_AVX2)
    if (K == 2 || K == 3)
    {
        PolyCompressAvx2P128(R, ROFT, V);
    }
    else
    {
        PolyCompressAvx2P160(R, ROFT, V);
    }
#else
    PolyCompress(R, ROFT, V, K);
#endif
}

void KyberBase::UnPackCiphertext(PolyVec &B, Poly &V, const std::vector<uint8_t> &C)
{
    const uint32_t K = static_cast<uint32_t>(B.vec.size());
    const size_t AOFT = (K > 3 ? 352 : 320) * K;

#if defined(CEX_HAS_AVX2)
    PolyVecDecompress(B, C);

    if (K == 2 || K == 3)
    {
        PolyDecompressAvx2P128(V, C, AOFT);
    }
    else
    {
        PolyDecompressAvx2P160(V, C, AOFT);
    }
#else
    PolyVecDecompress(B, C);
    PolyDecompress(V, C, AOFT, K);
#endif 
}

uint32_t KyberBase::RejUniform(Poly &R, uint32_t ROffset, uint32_t Rlen, const std::vector<uint8_t> &Buf, uint32_t BufLen)
{
    uint32_t ctr;
    uint32_t pos;
    uint16_t val0;
    uint16_t val1;

    ctr = 0;
    pos = 0;

    while (ctr < Rlen && pos + 3 <= BufLen)
    {
        val0 = static_cast<uint16_t>(((Buf[pos] >> 0) | (static_cast<uint16_t>(Buf[pos + 1]) << 8)) & 0x0FFF);
        val1 = static_cast<uint16_t>(((Buf[pos + 1] >> 4) | (static_cast<uint16_t>(Buf[pos + 2]) << 4)) & 0x0FFF);
        pos += 3;

        if (val0 < KYBER_Q)
        {
            R.coeffs[ROffset + ctr] = val0;
            ++ctr;
        }

        if (ctr < Rlen && val1 < KYBER_Q)
        {
            R.coeffs[ROffset + ctr] = val1;
            ++ctr;
        }
    }

    return ctr;
}

// kem.c

#if defined(CEX_HAS_AVX2)

void KyberBase::Cbd2(Poly &R, const std::vector<uint8_t> &Buf)
{
    __m256i f0;
    __m256i f1;
    __m256i f2;
    __m256i f3;
    const __m256i mask55 = _mm256_set1_epi32(0x55555555);
    const __m256i mask33 = _mm256_set1_epi32(0x33333333);
    const __m256i mask03 = _mm256_set1_epi32(0x03030303);
    const __m256i mask0F = _mm256_set1_epi32(0x0F0F0F0F);
    const uint8_t* pbuf = Buf.data();
    const int16_t* pr = R.coeffs.data();

    for (size_t i = 0; i < R.coeffs.size() / 64; ++i)
    {
        f0 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&pbuf[32 * i]));

        f1 = _mm256_srli_epi16(f0, 1);
        f0 = _mm256_and_si256(mask55, f0);
        f1 = _mm256_and_si256(mask55, f1);
        f0 = _mm256_add_epi8(f0, f1);

        f1 = _mm256_srli_epi16(f0, 2);
        f0 = _mm256_and_si256(mask33, f0);
        f1 = _mm256_and_si256(mask33, f1);
        f0 = _mm256_add_epi8(f0, mask33);
        f0 = _mm256_sub_epi8(f0, f1);

        f1 = _mm256_srli_epi16(f0, 4);
        f0 = _mm256_and_si256(mask0F, f0);
        f1 = _mm256_and_si256(mask0F, f1);
        f0 = _mm256_sub_epi8(f0, mask03);
        f1 = _mm256_sub_epi8(f1, mask03);

        f2 = _mm256_unpacklo_epi8(f0, f1);
        f3 = _mm256_unpackhi_epi8(f0, f1);

        f0 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f2));
        f1 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f2, 1));
        f2 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f3));
        f3 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f3, 1));

        _mm256_store_si256(reinterpret_cast<__m256i*>((uint8_t*)&pr[64 * i]), f0);
        _mm256_store_si256(reinterpret_cast<__m256i*>((uint8_t*)&pr[(64 * i) + 16]), f2);
        _mm256_store_si256(reinterpret_cast<__m256i*>((uint8_t*)&pr[(64 * i) + 32]), f1);
        _mm256_store_si256(reinterpret_cast<__m256i*>((uint8_t*)&pr[(64 * i) + 48]), f3);
    }
}

void KyberBase::Cbd3(Poly &R, const std::vector<uint8_t> &Buf)
{
    const __m256i mask249 = _mm256_set1_epi32(0x249249);
    const __m256i mask6DB = _mm256_set1_epi32(0x6DB6DB);
    const __m256i mask07 = _mm256_set1_epi32(7);
    const __m256i mask70 = _mm256_set1_epi32(7 << 16);
    const __m256i mask3 = _mm256_set1_epi16(3);
    const __m256i shufbidx = _mm256_set_epi8(-1, 15, 14, 13, -1, 12, 11, 10, -1, 9, 8, 7, -1, 6, 5, 4,
        -1, 11, 10, 9, -1, 8, 7, 6, -1, 5, 4, 3, -1, 2, 1, 0);
    __m256i f0;
    __m256i f1;
    __m256i f2;
    __m256i f3;
    size_t i;

    for (i = 0; i < R.coeffs.size() / 32; ++i)
    {
        f0 = _mm256_loadu_si256((__m256i*)&Buf[24 * i]);
        f0 = _mm256_permute4x64_epi64(f0, 0x94);
        f0 = _mm256_shuffle_epi8(f0, shufbidx);

        f1 = _mm256_srli_epi32(f0, 1);
        f2 = _mm256_srli_epi32(f0, 2);
        f0 = _mm256_and_si256(mask249, f0);
        f1 = _mm256_and_si256(mask249, f1);
        f2 = _mm256_and_si256(mask249, f2);
        f0 = _mm256_add_epi32(f0, f1);
        f0 = _mm256_add_epi32(f0, f2);

        f1 = _mm256_srli_epi32(f0, 3);
        f0 = _mm256_add_epi32(f0, mask6DB);
        f0 = _mm256_sub_epi32(f0, f1);

        f1 = _mm256_slli_epi32(f0, 10);
        f2 = _mm256_srli_epi32(f0, 12);
        f3 = _mm256_srli_epi32(f0, 2);
        f0 = _mm256_and_si256(f0, mask07);
        f1 = _mm256_and_si256(f1, mask70);
        f2 = _mm256_and_si256(f2, mask07);
        f3 = _mm256_and_si256(f3, mask70);
        f0 = _mm256_add_epi16(f0, f1);
        f1 = _mm256_add_epi16(f2, f3);
        f0 = _mm256_sub_epi16(f0, mask3);
        f1 = _mm256_sub_epi16(f1, mask3);

        f2 = _mm256_unpacklo_epi32(f0, f1);
        f3 = _mm256_unpackhi_epi32(f0, f1);

        f0 = _mm256_permute2x128_si256(f2, f3, 0x20);
        f1 = _mm256_permute2x128_si256(f2, f3, 0x31);

        _mm256_store_si256((__m256i*)&R.coeffs[32 * i], f0);
        _mm256_store_si256((__m256i*)&R.coeffs[32 * i + 16], f1);
    }
}

void KyberBase::PolyCompressAvx2P128(std::vector<uint8_t> &R, size_t ROffset, const Poly &A)
{
    const __m256i v = _mm256_set1_epi16(20159);
    const __m256i shift1 = _mm256_set1_epi16(1 << 9);
    const __m256i mask = _mm256_set1_epi16(15);
    const __m256i shift2 = _mm256_set1_epi16((16 << 8) + 1);
    const __m256i permdidx = _mm256_set_epi32(7, 3, 6, 2, 5, 1, 4, 0);
    const int16_t* pa = A.coeffs.data();
    uint8_t* pr = R.data() + ROffset;
    __m256i f0;
    __m256i f1;
    __m256i f2;
    __m256i f3;

    for (size_t i = 0; i < A.coeffs.size() / 64; ++i)
    {
        f0 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&pa[64 * i]));
        f1 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&pa[(64 * i) + 16]));
        f2 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&pa[(64 * i) + 32]));
        f3 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&pa[(64 * i) + 48]));
        f0 = _mm256_mulhi_epi16(f0, v);
        f1 = _mm256_mulhi_epi16(f1, v);
        f2 = _mm256_mulhi_epi16(f2, v);
        f3 = _mm256_mulhi_epi16(f3, v);
        f0 = _mm256_mulhrs_epi16(f0, shift1);
        f1 = _mm256_mulhrs_epi16(f1, shift1);
        f2 = _mm256_mulhrs_epi16(f2, shift1);
        f3 = _mm256_mulhrs_epi16(f3, shift1);
        f0 = _mm256_and_si256(f0, mask);
        f1 = _mm256_and_si256(f1, mask);
        f2 = _mm256_and_si256(f2, mask);
        f3 = _mm256_and_si256(f3, mask);
        f0 = _mm256_packus_epi16(f0, f1);
        f2 = _mm256_packus_epi16(f2, f3);
        f0 = _mm256_maddubs_epi16(f0, shift2);
        f2 = _mm256_maddubs_epi16(f2, shift2);
        f0 = _mm256_packus_epi16(f0, f2);
        f0 = _mm256_permutevar8x32_epi32(f0, permdidx);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&pr[32 * i]), f0);
    }
}

void KyberBase::PolyDecompressAvx2P128(Poly &R, const std::vector<uint8_t> &A, size_t AOffset)
{
    const __m256i q = _mm256_set1_epi16(KYBER_Q);
    const __m256i shufbidx = _mm256_set_epi8(7, 7, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4,
        3, 3, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0);
    const __m256i mask = _mm256_set1_epi32(0x00F0000F);
    const __m256i shift = _mm256_set1_epi32((128 << 16) + 2048);
    __m256i f;
    int16_t* pr = R.coeffs.data();
    const uint8_t* pa = A.data() + AOffset;

    for (size_t i = 0; i < R.coeffs.size() / 16; ++i)
    {
        f = _mm256_broadcastq_epi64(_mm_loadl_epi64(reinterpret_cast<const __m128i*>(&pa[8 * i])));
        f = _mm256_shuffle_epi8(f, shufbidx);
        f = _mm256_and_si256(f, mask);
        f = _mm256_mullo_epi16(f, shift);
        f = _mm256_mulhrs_epi16(f, q);
        _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[16 * i]), f);
    }
}

void KyberBase::PolyCompressAvx2P160(std::vector<uint8_t> &R, size_t ROffset, const Poly &A)
{
    const __m256i v = _mm256_set1_epi16(20159);
    const __m256i shift1 = _mm256_set1_epi16(1 << 10);
    const __m256i mask = _mm256_set1_epi16(31);
    const __m256i shift2 = _mm256_set1_epi16((32 << 8) + 1);
    const __m256i shift3 = _mm256_set1_epi32((1024 << 16) + 1);
    const __m256i sllvdidx = _mm256_set1_epi64x(12);
    const __m256i shufbidx = _mm256_set_epi8(8, -1, -1, -1, -1, -1, 4, 3, 2, 1, 0, -1, 12, 11, 10, 9,
        -1, 12, 11, 10, 9, 8, -1, -1, -1, -1, -1, 4, 3, 2, 1, 0);
    __m256i f0;
    __m256i f1;
    __m128i t0;
    __m128i t1;
    const int16_t* pa = A.coeffs.data();
    uint8_t* pr = R.data() + ROffset;

    for (size_t i = 0; i < A.coeffs.size() / 32; ++i)
    {
        f0 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&pa[32 * i]));
        f1 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&pa[(32 * i) + 16]));
        f0 = _mm256_mulhi_epi16(f0, v);
        f1 = _mm256_mulhi_epi16(f1, v);
        f0 = _mm256_mulhrs_epi16(f0, shift1);
        f1 = _mm256_mulhrs_epi16(f1, shift1);
        f0 = _mm256_and_si256(f0, mask);
        f1 = _mm256_and_si256(f1, mask);
        f0 = _mm256_packus_epi16(f0, f1);
        f0 = _mm256_maddubs_epi16(f0, shift2);
        f0 = _mm256_madd_epi16(f0, shift3);
        f0 = _mm256_sllv_epi32(f0, sllvdidx);
        f0 = _mm256_srlv_epi64(f0, sllvdidx);
        f0 = _mm256_shuffle_epi8(f0, shufbidx);
        t0 = _mm256_castsi256_si128(f0);
        t1 = _mm256_extracti128_si256(f0, 1);
        t0 = _mm_blendv_epi8(t0, t1, _mm256_castsi256_si128(shufbidx));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&pr[20 * i]), t0);
        _mm_store_ss(reinterpret_cast<float*>(&pr[(20 * i) + 16]), _mm_castsi128_ps(t1));
    }
}

void KyberBase::PolyDecompressAvx2P160(Poly &R, const std::vector<uint8_t> &A, size_t AOffset)
{
    const __m256i q = _mm256_set1_epi16(KYBER_Q);
    const __m256i shufbidx = _mm256_set_epi8(9, 9, 9, 8, 8, 8, 8, 7, 7, 6, 6, 6, 6, 5, 5, 5,
        4, 4, 4, 3, 3, 3, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0);
    const __m256i mask = _mm256_set_epi16(248, 1984, 62, 496, 3968, 124, 992, 31,
        248, 1984, 62, 496, 3968, 124, 992, 31);
    const __m256i shift = _mm256_set_epi16(128, 16, 512, 64, 8, 256, 32, 1024,
        128, 16, 512, 64, 8, 256, 32, 1024);
    __m256i f;
    int16_t* pr = R.coeffs.data();
    const uint8_t* pa = A.data() + AOffset;

    for (size_t i = 0; i < R.coeffs.size() / 16; ++i)
    {
        f = _mm256_broadcastsi128_si256(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&pa[10 * i])));
        f = _mm256_shuffle_epi8(f, shufbidx);
        f = _mm256_and_si256(f, mask);
        f = _mm256_mullo_epi16(f, shift);
        f = _mm256_mulhrs_epi16(f, q);
        _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[16 * i]), f);
    }
}

void KyberBase::PolyFromMsg(Poly &R, const std::vector<uint8_t> &Msg)
{
    const __m256i shift = _mm256_broadcastsi128_si256(_mm_set_epi32(0, 1, 2, 3));
    const __m256i idx = _mm256_broadcastsi128_si256(_mm_set_epi8(15, 14, 11, 10, 7, 6, 3, 2, 13, 12, 9, 8, 5, 4, 1, 0));
    const __m256i hqs = _mm256_set1_epi16((KYBER_Q + 1) / 2);
    __m256i f;
    __m256i g0;
    __m256i g1;
    __m256i g2;
    __m256i g3;
    __m256i h0;
    __m256i h1;
    __m256i h2;
    __m256i h3;
    int16_t* pr = R.coeffs.data();
    const uint8_t* pm = Msg.data();

    f = _mm256_load_si256(reinterpret_cast<const __m256i*>(pm));
    g3 = _mm256_shuffle_epi32(f, 0);
    g3 = _mm256_sllv_epi32(g3, shift);
    g3 = _mm256_shuffle_epi8(g3, idx);
    g0 = _mm256_slli_epi16(g3, 12);
    g1 = _mm256_slli_epi16(g3, 8);
    g2 = _mm256_slli_epi16(g3, 4);
    g0 = _mm256_srai_epi16(g0, 15);
    g1 = _mm256_srai_epi16(g1, 15);
    g2 = _mm256_srai_epi16(g2, 15);
    g3 = _mm256_srai_epi16(g3, 15);
    g0 = _mm256_and_si256(g0, hqs);  /* 19 18 17 16  3  2  1  0 */
    g1 = _mm256_and_si256(g1, hqs);  /* 23 22 21 20  7  6  5  4 */
    g2 = _mm256_and_si256(g2, hqs);  /* 27 26 25 24 11 10  9  8 */
    g3 = _mm256_and_si256(g3, hqs);  /* 31 30 29 28 15 14 13 12 */
    h0 = _mm256_unpacklo_epi64(g0, g1);
    h2 = _mm256_unpackhi_epi64(g0, g1);
    h1 = _mm256_unpacklo_epi64(g2, g3);
    h3 = _mm256_unpackhi_epi64(g2, g3);
    g0 = _mm256_permute2x128_si256(h0, h1, 0x20);
    g2 = _mm256_permute2x128_si256(h0, h1, 0x31);
    g1 = _mm256_permute2x128_si256(h2, h3, 0x20);
    g3 = _mm256_permute2x128_si256(h2, h3, 0x31);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[0]), g0);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[16]), g1);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[128]), g2);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[128 + 16]), g3);

    g3 = _mm256_shuffle_epi32(f, 0x55 * 1);
    g3 = _mm256_sllv_epi32(g3, shift);
    g3 = _mm256_shuffle_epi8(g3, idx);
    g0 = _mm256_slli_epi16(g3, 12);
    g1 = _mm256_slli_epi16(g3, 8);
    g2 = _mm256_slli_epi16(g3, 4);
    g0 = _mm256_srai_epi16(g0, 15);
    g1 = _mm256_srai_epi16(g1, 15);
    g2 = _mm256_srai_epi16(g2, 15);
    g3 = _mm256_srai_epi16(g3, 15);
    g0 = _mm256_and_si256(g0, hqs);
    g1 = _mm256_and_si256(g1, hqs);
    g2 = _mm256_and_si256(g2, hqs);
    g3 = _mm256_and_si256(g3, hqs);
    h0 = _mm256_unpacklo_epi64(g0, g1);
    h2 = _mm256_unpackhi_epi64(g0, g1);
    h1 = _mm256_unpacklo_epi64(g2, g3);
    h3 = _mm256_unpackhi_epi64(g2, g3);
    g0 = _mm256_permute2x128_si256(h0, h1, 0x20);
    g2 = _mm256_permute2x128_si256(h0, h1, 0x31);
    g1 = _mm256_permute2x128_si256(h2, h3, 0x20);
    g3 = _mm256_permute2x128_si256(h2, h3, 0x31);
    _mm256_store_si256(reinterpret_cast<__m256i *>(&pr[32]), g0);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[32 + 16]), g1);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[128 + 32]), g2);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[128 + 32 + 16]), g3);

    g3 = _mm256_shuffle_epi32(f, 0x55 * 2);
    g3 = _mm256_sllv_epi32(g3, shift);
    g3 = _mm256_shuffle_epi8(g3, idx);
    g0 = _mm256_slli_epi16(g3, 12);
    g1 = _mm256_slli_epi16(g3, 8);
    g2 = _mm256_slli_epi16(g3, 4);
    g0 = _mm256_srai_epi16(g0, 15);
    g1 = _mm256_srai_epi16(g1, 15);
    g2 = _mm256_srai_epi16(g2, 15);
    g3 = _mm256_srai_epi16(g3, 15);
    g0 = _mm256_and_si256(g0, hqs);
    g1 = _mm256_and_si256(g1, hqs);
    g2 = _mm256_and_si256(g2, hqs);
    g3 = _mm256_and_si256(g3, hqs);
    h0 = _mm256_unpacklo_epi64(g0, g1);
    h2 = _mm256_unpackhi_epi64(g0, g1);
    h1 = _mm256_unpacklo_epi64(g2, g3);
    h3 = _mm256_unpackhi_epi64(g2, g3);
    g0 = _mm256_permute2x128_si256(h0, h1, 0x20);
    g2 = _mm256_permute2x128_si256(h0, h1, 0x31);
    g1 = _mm256_permute2x128_si256(h2, h3, 0x20);
    g3 = _mm256_permute2x128_si256(h2, h3, 0x31);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[32 * 2]), g0);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[(32 * 2) + 16]), g1);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[128 + (32 * 2)]), g2);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[128 + (32 * 2) + 16]), g3);

    g3 = _mm256_shuffle_epi32(f, 0x55 * 3);
    g3 = _mm256_sllv_epi32(g3, shift);
    g3 = _mm256_shuffle_epi8(g3, idx);
    g0 = _mm256_slli_epi16(g3, 12);
    g1 = _mm256_slli_epi16(g3, 8);
    g2 = _mm256_slli_epi16(g3, 4);
    g0 = _mm256_srai_epi16(g0, 15);
    g1 = _mm256_srai_epi16(g1, 15);
    g2 = _mm256_srai_epi16(g2, 15);
    g3 = _mm256_srai_epi16(g3, 15);
    g0 = _mm256_and_si256(g0, hqs);
    g1 = _mm256_and_si256(g1, hqs);
    g2 = _mm256_and_si256(g2, hqs);
    g3 = _mm256_and_si256(g3, hqs);
    h0 = _mm256_unpacklo_epi64(g0, g1);
    h2 = _mm256_unpackhi_epi64(g0, g1);
    h1 = _mm256_unpacklo_epi64(g2, g3);
    h3 = _mm256_unpackhi_epi64(g2, g3);
    g0 = _mm256_permute2x128_si256(h0, h1, 0x20);
    g2 = _mm256_permute2x128_si256(h0, h1, 0x31);
    g1 = _mm256_permute2x128_si256(h2, h3, 0x20);
    g3 = _mm256_permute2x128_si256(h2, h3, 0x31);

    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[32 * 3]), g0);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[(32 * 3) + 16]), g1);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[128 + (32 * 3)]), g2);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[128 + (32 * 3) + 16]), g3);
}

void KyberBase::PolyAdd(Poly &R, const Poly &A, const Poly &B)
{
    const int16_t* pa = A.coeffs.data();
    const int16_t* pb = B.coeffs.data();
    int16_t* pr = R.coeffs.data();
    __m256i f0;
    __m256i f1;

    for (size_t i = 0; i < R.coeffs.size(); i += 16)
    {
        f0 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&pa[i]));
        f1 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&pb[i]));
        f0 = _mm256_add_epi16(f0, f1);

        _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[i]), f0);
    }
}

void KyberBase::PolySub(Poly &R, const Poly &A, const Poly &B)
{
    const int16_t* pa = A.coeffs.data();
    const int16_t* pb = B.coeffs.data();
    int16_t* pr = R.coeffs.data();
    __m256i f0;
    __m256i f1;

    for (size_t i = 0; i < R.coeffs.size(); i += 16)
    {
        f0 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&pa[i]));
        f1 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&pb[i]));
        f0 = _mm256_sub_epi16(f0, f1);
        _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[i]), f0);
    }
}

void KyberBase::PolyDecompress10Avx2P320(Poly &R, const std::vector<uint8_t> &A, size_t AOffset)
{
    const __m256i q = _mm256_set1_epi32((KYBER_Q << 16) + 4 * KYBER_Q);
    const __m256i shufbidx = _mm256_set_epi8(11, 10, 10, 9, 9, 8, 8, 7,
        6, 5, 5, 4, 4, 3, 3, 2, 9, 8, 8, 7, 7, 6, 6, 5, 4, 3, 3, 2, 2, 1, 1, 0);
    const __m256i sllvdidx = _mm256_set1_epi64x(4);
    const __m256i mask = _mm256_set1_epi32((32736 << 16) + 8184);
    __m256i f;
    int16_t* pr = R.coeffs.data();
    const uint8_t* pa = A.data() + AOffset;

    for (size_t i = 0; i < R.coeffs.size() / 16; ++i)
    {
        f = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&pa[20 * i]));
        f = _mm256_permute4x64_epi64(f, 0x94);
        f = _mm256_shuffle_epi8(f, shufbidx);
        f = _mm256_sllv_epi32(f, sllvdidx);
        f = _mm256_srli_epi16(f, 1);
        f = _mm256_and_si256(f, mask);
        f = _mm256_mulhrs_epi16(f, q);
        _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[16 * i]), f);
    }
}

void KyberBase::PolyDecompress11Avx2P352(Poly &R, const std::vector<uint8_t> &A, size_t AOffset)
{
    const __m256i q = _mm256_set1_epi16(KYBER_Q);
    const __m256i shufbidx = _mm256_set_epi8(13, 12, 12, 11, 10, 9, 9, 8,
        8, 7, 6, 5, 5, 4, 4, 3, 10, 9, 9, 8, 7, 6, 6, 5, 5, 4, 3, 2, 2, 1, 1, 0);
    const __m256i srlvdidx = _mm256_set_epi32(0, 0, 1, 0, 0, 0, 1, 0);
    const __m256i srlvqidx = _mm256_set_epi64x(2, 0, 2, 0);
    const __m256i shift = _mm256_set_epi16(4, 32, 1, 8, 32, 1, 4, 32, 4, 32, 1, 8, 32, 1, 4, 32);
    const __m256i mask = _mm256_set1_epi16(32752);
    __m256i f;
    int16_t* pr = R.coeffs.data();
    const uint8_t* pa = A.data() + AOffset;

    for (size_t i = 0; i < R.coeffs.size() / 16; ++i)
    {
        f = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&pa[22 * i]));
        f = _mm256_permute4x64_epi64(f, 0x94);
        f = _mm256_shuffle_epi8(f, shufbidx);
        f = _mm256_srlv_epi32(f, srlvdidx);
        f = _mm256_srlv_epi64(f, srlvqidx);
        f = _mm256_mullo_epi16(f, shift);
        f = _mm256_srli_epi16(f, 1);
        f = _mm256_and_si256(f, mask);
        f = _mm256_mulhrs_epi16(f, q);
        _mm256_store_si256(reinterpret_cast<__m256i*>(&pr[16 * i]), f);
    }
}

void KyberBase::PolyVecDecompress(PolyVec &R, const std::vector<uint8_t> &A)
{
    if (R.vec.size() == 2 || R.vec.size() == 3)
    {
        for (size_t i = 0; i < R.vec.size(); ++i)
        {
            PolyDecompress10Avx2P320(R.vec[i], A, 320 * i);
        }
    }
    else
    {
        for (size_t i = 0; i < R.vec.size(); ++i)
        {
            PolyDecompress11Avx2P352(R.vec[i], A, 352 * i);
        }
    }
}

uint32_t KyberBase::RejUniformAvx2(Poly &R, const std::vector<uint8_t> &Buf)
{
    static const int8_t KYBER_REJ_IDX[KYBER_N][8] =
    {
        { -1, -1, -1, -1, -1, -1, -1, -1 }, { 0, -1, -1, -1, -1, -1, -1, -1 },
        { 2, -1, -1, -1, -1, -1, -1, -1 }, { 0,  2, -1, -1, -1, -1, -1, -1 },
        { 4, -1, -1, -1, -1, -1, -1, -1 }, { 0,  4, -1, -1, -1, -1, -1, -1 },
        { 2,  4, -1, -1, -1, -1, -1, -1 }, { 0,  2,  4, -1, -1, -1, -1, -1 },
        { 6, -1, -1, -1, -1, -1, -1, -1 }, { 0,  6, -1, -1, -1, -1, -1, -1 },
        { 2,  6, -1, -1, -1, -1, -1, -1 }, { 0,  2,  6, -1, -1, -1, -1, -1 },
        { 4,  6, -1, -1, -1, -1, -1, -1 }, { 0,  4,  6, -1, -1, -1, -1, -1 },
        { 2,  4,  6, -1, -1, -1, -1, -1 }, { 0,  2,  4,  6, -1, -1, -1, -1 },
        { 8, -1, -1, -1, -1, -1, -1, -1 }, { 0,  8, -1, -1, -1, -1, -1, -1 },
        { 2,  8, -1, -1, -1, -1, -1, -1 }, { 0,  2,  8, -1, -1, -1, -1, -1 },
        { 4,  8, -1, -1, -1, -1, -1, -1 }, { 0,  4,  8, -1, -1, -1, -1, -1 },
        { 2,  4,  8, -1, -1, -1, -1, -1 }, { 0,  2,  4,  8, -1, -1, -1, -1 },
        { 6,  8, -1, -1, -1, -1, -1, -1 }, { 0,  6,  8, -1, -1, -1, -1, -1 },
        { 2,  6,  8, -1, -1, -1, -1, -1 }, { 0,  2,  6,  8, -1, -1, -1, -1 },
        { 4,  6,  8, -1, -1, -1, -1, -1 }, { 0,  4,  6,  8, -1, -1, -1, -1 },
        { 2,  4,  6,  8, -1, -1, -1, -1 }, { 0,  2,  4,  6,  8, -1, -1, -1 },
        { 10, -1, -1, -1, -1, -1, -1, -1 },{ 0, 10, -1, -1, -1, -1, -1, -1 },
        { 2, 10, -1, -1, -1, -1, -1, -1 }, { 0,  2, 10, -1, -1, -1, -1, -1 },
        { 4, 10, -1, -1, -1, -1, -1, -1 }, { 0,  4, 10, -1, -1, -1, -1, -1 },
        { 2,  4, 10, -1, -1, -1, -1, -1 }, { 0,  2,  4, 10, -1, -1, -1, -1 },
        { 6, 10, -1, -1, -1, -1, -1, -1 }, { 0,  6, 10, -1, -1, -1, -1, -1 },
        { 2,  6, 10, -1, -1, -1, -1, -1 }, { 0,  2,  6, 10, -1, -1, -1, -1 },
        { 4,  6, 10, -1, -1, -1, -1, -1 }, { 0,  4,  6, 10, -1, -1, -1, -1 },
        { 2,  4,  6, 10, -1, -1, -1, -1 }, { 0,  2,  4,  6, 10, -1, -1, -1 },
        { 8, 10, -1, -1, -1, -1, -1, -1 }, { 0,  8, 10, -1, -1, -1, -1, -1 },
        { 2,  8, 10, -1, -1, -1, -1, -1 }, { 0,  2,  8, 10, -1, -1, -1, -1 },
        { 4,  8, 10, -1, -1, -1, -1, -1 }, { 0,  4,  8, 10, -1, -1, -1, -1 },
        { 2,  4,  8, 10, -1, -1, -1, -1 }, { 0,  2,  4,  8, 10, -1, -1, -1 },
        { 6,  8, 10, -1, -1, -1, -1, -1 }, { 0,  6,  8, 10, -1, -1, -1, -1 },
        { 2,  6,  8, 10, -1, -1, -1, -1 }, { 0,  2,  6,  8, 10, -1, -1, -1 },
        { 4,  6,  8, 10, -1, -1, -1, -1 }, { 0,  4,  6,  8, 10, -1, -1, -1 },
        { 2,  4,  6,  8, 10, -1, -1, -1 }, { 0,  2,  4,  6,  8, 10, -1, -1 },
        { 12, -1, -1, -1, -1, -1, -1, -1 }, { 0, 12, -1, -1, -1, -1, -1, -1 },
        { 2, 12, -1, -1, -1, -1, -1, -1 }, { 0,  2, 12, -1, -1, -1, -1, -1 },
        { 4, 12, -1, -1, -1, -1, -1, -1 }, { 0,  4, 12, -1, -1, -1, -1, -1 },
        { 2,  4, 12, -1, -1, -1, -1, -1 }, { 0,  2,  4, 12, -1, -1, -1, -1 },
        { 6, 12, -1, -1, -1, -1, -1, -1 }, { 0,  6, 12, -1, -1, -1, -1, -1 },
        { 2,  6, 12, -1, -1, -1, -1, -1 }, { 0,  2,  6, 12, -1, -1, -1, -1 },
        { 4,  6, 12, -1, -1, -1, -1, -1 }, { 0,  4,  6, 12, -1, -1, -1, -1 },
        { 2,  4,  6, 12, -1, -1, -1, -1 }, { 0,  2,  4,  6, 12, -1, -1, -1 },
        { 8, 12, -1, -1, -1, -1, -1, -1 }, { 0,  8, 12, -1, -1, -1, -1, -1 },
        { 2,  8, 12, -1, -1, -1, -1, -1 }, { 0,  2,  8, 12, -1, -1, -1, -1 },
        { 4,  8, 12, -1, -1, -1, -1, -1 }, { 0,  4,  8, 12, -1, -1, -1, -1 },
        { 2,  4,  8, 12, -1, -1, -1, -1 }, { 0,  2,  4,  8, 12, -1, -1, -1 },
        { 6,  8, 12, -1, -1, -1, -1, -1 }, { 0,  6,  8, 12, -1, -1, -1, -1 },
        { 2,  6,  8, 12, -1, -1, -1, -1 }, { 0,  2,  6,  8, 12, -1, -1, -1 },
        { 4,  6,  8, 12, -1, -1, -1, -1 }, { 0,  4,  6,  8, 12, -1, -1, -1 },
        { 2,  4,  6,  8, 12, -1, -1, -1 }, { 0,  2,  4,  6,  8, 12, -1, -1 },
        { 10, 12, -1, -1, -1, -1, -1, -1 }, { 0, 10, 12, -1, -1, -1, -1, -1 },
        { 2, 10, 12, -1, -1, -1, -1, -1 }, { 0,  2, 10, 12, -1, -1, -1, -1 },
        { 4, 10, 12, -1, -1, -1, -1, -1 }, { 0,  4, 10, 12, -1, -1, -1, -1 },
        { 2,  4, 10, 12, -1, -1, -1, -1 }, { 0,  2,  4, 10, 12, -1, -1, -1 },
        { 6, 10, 12, -1, -1, -1, -1, -1 }, { 0,  6, 10, 12, -1, -1, -1, -1 },
        { 2,  6, 10, 12, -1, -1, -1, -1 }, { 0,  2,  6, 10, 12, -1, -1, -1 },
        { 4,  6, 10, 12, -1, -1, -1, -1 }, { 0,  4,  6, 10, 12, -1, -1, -1 },
        { 2,  4,  6, 10, 12, -1, -1, -1 }, { 0,  2,  4,  6, 10, 12, -1, -1 },
        { 8, 10, 12, -1, -1, -1, -1, -1 }, { 0,  8, 10, 12, -1, -1, -1, -1 },
        { 2,  8, 10, 12, -1, -1, -1, -1 }, { 0,  2,  8, 10, 12, -1, -1, -1 },
        { 4,  8, 10, 12, -1, -1, -1, -1 }, { 0,  4,  8, 10, 12, -1, -1, -1 },
        { 2,  4,  8, 10, 12, -1, -1, -1 }, { 0,  2,  4,  8, 10, 12, -1, -1 },
        { 6,  8, 10, 12, -1, -1, -1, -1 }, { 0,  6,  8, 10, 12, -1, -1, -1 },
        { 2,  6,  8, 10, 12, -1, -1, -1 }, { 0,  2,  6,  8, 10, 12, -1, -1 },
        { 4,  6,  8, 10, 12, -1, -1, -1 }, { 0,  4,  6,  8, 10, 12, -1, -1 },
        { 2,  4,  6,  8, 10, 12, -1, -1 }, { 0,  2,  4,  6,  8, 10, 12, -1 },
        { 14, -1, -1, -1, -1, -1, -1, -1 }, { 0, 14, -1, -1, -1, -1, -1, -1 },
        { 2, 14, -1, -1, -1, -1, -1, -1 }, { 0,  2, 14, -1, -1, -1, -1, -1 },
        { 4, 14, -1, -1, -1, -1, -1, -1 }, { 0,  4, 14, -1, -1, -1, -1, -1 },
        { 2,  4, 14, -1, -1, -1, -1, -1 }, { 0,  2,  4, 14, -1, -1, -1, -1 },
        { 6, 14, -1, -1, -1, -1, -1, -1 }, { 0,  6, 14, -1, -1, -1, -1, -1 },
        { 2,  6, 14, -1, -1, -1, -1, -1 }, { 0,  2,  6, 14, -1, -1, -1, -1 },
        { 4,  6, 14, -1, -1, -1, -1, -1 }, { 0,  4,  6, 14, -1, -1, -1, -1 },
        { 2,  4,  6, 14, -1, -1, -1, -1 }, { 0,  2,  4,  6, 14, -1, -1, -1 },
        { 8, 14, -1, -1, -1, -1, -1, -1 }, { 0,  8, 14, -1, -1, -1, -1, -1 },
        { 2,  8, 14, -1, -1, -1, -1, -1 }, { 0,  2,  8, 14, -1, -1, -1, -1 },
        { 4,  8, 14, -1, -1, -1, -1, -1 }, { 0,  4,  8, 14, -1, -1, -1, -1 },
        { 2,  4,  8, 14, -1, -1, -1, -1 }, { 0,  2,  4,  8, 14, -1, -1, -1 },
        { 6,  8, 14, -1, -1, -1, -1, -1 }, { 0,  6,  8, 14, -1, -1, -1, -1 },
        { 2,  6,  8, 14, -1, -1, -1, -1 }, { 0,  2,  6,  8, 14, -1, -1, -1 },
        { 4,  6,  8, 14, -1, -1, -1, -1 }, { 0,  4,  6,  8, 14, -1, -1, -1 },
        { 2,  4,  6,  8, 14, -1, -1, -1 }, { 0,  2,  4,  6,  8, 14, -1, -1 },
        { 10, 14, -1, -1, -1, -1, -1, -1 }, { 0, 10, 14, -1, -1, -1, -1, -1 },
        { 2, 10, 14, -1, -1, -1, -1, -1 }, { 0,  2, 10, 14, -1, -1, -1, -1 },
        { 4, 10, 14, -1, -1, -1, -1, -1 }, { 0,  4, 10, 14, -1, -1, -1, -1 },
        { 2,  4, 10, 14, -1, -1, -1, -1 }, { 0,  2,  4, 10, 14, -1, -1, -1 },
        { 6, 10, 14, -1, -1, -1, -1, -1 }, { 0,  6, 10, 14, -1, -1, -1, -1 },
        { 2,  6, 10, 14, -1, -1, -1, -1 }, { 0,  2,  6, 10, 14, -1, -1, -1 },
        { 4,  6, 10, 14, -1, -1, -1, -1 }, { 0,  4,  6, 10, 14, -1, -1, -1 },
        { 2,  4,  6, 10, 14, -1, -1, -1 }, { 0,  2,  4,  6, 10, 14, -1, -1 },
        { 8, 10, 14, -1, -1, -1, -1, -1 }, { 0,  8, 10, 14, -1, -1, -1, -1 },
        { 2,  8, 10, 14, -1, -1, -1, -1 }, { 0,  2,  8, 10, 14, -1, -1, -1 },
        { 4,  8, 10, 14, -1, -1, -1, -1 }, { 0,  4,  8, 10, 14, -1, -1, -1 },
        { 2,  4,  8, 10, 14, -1, -1, -1 }, { 0,  2,  4,  8, 10, 14, -1, -1 },
        { 6,  8, 10, 14, -1, -1, -1, -1 }, { 0,  6,  8, 10, 14, -1, -1, -1 },
        { 2,  6,  8, 10, 14, -1, -1, -1 }, { 0,  2,  6,  8, 10, 14, -1, -1 },
        { 4,  6,  8, 10, 14, -1, -1, -1 }, { 0,  4,  6,  8, 10, 14, -1, -1 },
        { 2,  4,  6,  8, 10, 14, -1, -1 }, { 0,  2,  4,  6,  8, 10, 14, -1 },
        { 12, 14, -1, -1, -1, -1, -1, -1 }, { 0, 12, 14, -1, -1, -1, -1, -1 },
        { 2, 12, 14, -1, -1, -1, -1, -1 }, { 0,  2, 12, 14, -1, -1, -1, -1 },
        { 4, 12, 14, -1, -1, -1, -1, -1 }, { 0,  4, 12, 14, -1, -1, -1, -1 },
        { 2,  4, 12, 14, -1, -1, -1, -1 }, { 0,  2,  4, 12, 14, -1, -1, -1 },
        { 6, 12, 14, -1, -1, -1, -1, -1 }, { 0,  6, 12, 14, -1, -1, -1, -1 },
        { 2,  6, 12, 14, -1, -1, -1, -1 }, { 0,  2,  6, 12, 14, -1, -1, -1 },
        { 4,  6, 12, 14, -1, -1, -1, -1 }, { 0,  4,  6, 12, 14, -1, -1, -1 },
        { 2,  4,  6, 12, 14, -1, -1, -1 }, { 0,  2,  4,  6, 12, 14, -1, -1 },
        { 8, 12, 14, -1, -1, -1, -1, -1 }, { 0,  8, 12, 14, -1, -1, -1, -1 },
        { 2,  8, 12, 14, -1, -1, -1, -1 }, { 0,  2,  8, 12, 14, -1, -1, -1 },
        { 4,  8, 12, 14, -1, -1, -1, -1 }, { 0,  4,  8, 12, 14, -1, -1, -1 },
        { 2,  4,  8, 12, 14, -1, -1, -1 }, { 0,  2,  4,  8, 12, 14, -1, -1 },
        { 6,  8, 12, 14, -1, -1, -1, -1 }, { 0,  6,  8, 12, 14, -1, -1, -1 },
        { 2,  6,  8, 12, 14, -1, -1, -1 }, { 0,  2,  6,  8, 12, 14, -1, -1 },
        { 4,  6,  8, 12, 14, -1, -1, -1 }, { 0,  4,  6,  8, 12, 14, -1, -1 },
        { 2,  4,  6,  8, 12, 14, -1, -1 }, { 0,  2,  4,  6,  8, 12, 14, -1 },
        { 10, 12, 14, -1, -1, -1, -1, -1 }, { 0, 10, 12, 14, -1, -1, -1, -1 },
        { 2, 10, 12, 14, -1, -1, -1, -1 }, { 0,  2, 10, 12, 14, -1, -1, -1 },
        { 4, 10, 12, 14, -1, -1, -1, -1 }, { 0,  4, 10, 12, 14, -1, -1, -1 },
        { 2,  4, 10, 12, 14, -1, -1, -1 }, { 0,  2,  4, 10, 12, 14, -1, -1 },
        { 6, 10, 12, 14, -1, -1, -1, -1 }, { 0,  6, 10, 12, 14, -1, -1, -1 },
        { 2,  6, 10, 12, 14, -1, -1, -1 }, { 0,  2,  6, 10, 12, 14, -1, -1 },
        { 4,  6, 10, 12, 14, -1, -1, -1 }, { 0,  4,  6, 10, 12, 14, -1, -1 },
        { 2,  4,  6, 10, 12, 14, -1, -1 }, { 0,  2,  4,  6, 10, 12, 14, -1 },
        { 8, 10, 12, 14, -1, -1, -1, -1 }, { 0,  8, 10, 12, 14, -1, -1, -1 },
        { 2,  8, 10, 12, 14, -1, -1, -1 }, { 0,  2,  8, 10, 12, 14, -1, -1 },
        { 4,  8, 10, 12, 14, -1, -1, -1 }, { 0,  4,  8, 10, 12, 14, -1, -1 },
        { 2,  4,  8, 10, 12, 14, -1, -1 }, { 0,  2,  4,  8, 10, 12, 14, -1 },
        { 6,  8, 10, 12, 14, -1, -1, -1 }, { 0,  6,  8, 10, 12, 14, -1, -1 },
        { 2,  6,  8, 10, 12, 14, -1, -1 }, { 0,  2,  6,  8, 10, 12, 14, -1 },
        { 4,  6,  8, 10, 12, 14, -1, -1 }, { 0,  4,  6,  8, 10, 12, 14, -1 },
        { 2,  4,  6,  8, 10, 12, 14, -1 }, { 0,  2,  4,  6,  8, 10, 12, 14 }
    };

    const int32_t AVX_REJ_UNIFORM_BUFLEN = 504;
    const __m256i bound = _mm256_set1_epi16(KYBER_Q);
    const __m256i ones = _mm256_set1_epi8(1);
    const __m256i mask = _mm256_set1_epi16(0xFFF);
    const __m256i idx8 = _mm256_set_epi8(15, 14, 14, 13, 12, 11, 11, 10,
        9, 8, 8, 7, 6, 5, 5, 4, 11, 10, 10, 9, 8, 7, 7, 6, 5, 4, 4, 3, 2, 1, 1, 0);
    __m256i f0;
    __m256i f1;
    __m256i g0;
    __m256i g1;
    __m256i g2;
    __m256i g3;
    __m128i f;
    __m128i t;
    __m128i pilo;
    __m128i pihi;
    uint32_t ctr;
    uint32_t pos;
    uint16_t val0;
    uint16_t val1;
    uint32_t good;

    ctr = 0;
    pos = 0;
    const uint8_t* pbuff = Buf.data();
    int16_t* pr = R.coeffs.data();

    while (ctr <= KYBER_N - 32 && pos <= AVX_REJ_UNIFORM_BUFLEN - 48)
    {
        f0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&pbuff[pos]));
        f1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&pbuff[pos + 24]));
        f0 = _mm256_permute4x64_epi64(f0, 0x94);
        f1 = _mm256_permute4x64_epi64(f1, 0x94);
        f0 = _mm256_shuffle_epi8(f0, idx8);
        f1 = _mm256_shuffle_epi8(f1, idx8);
        g0 = _mm256_srli_epi16(f0, 4);
        g1 = _mm256_srli_epi16(f1, 4);
        f0 = _mm256_blend_epi16(f0, g0, 0xAA);
        f1 = _mm256_blend_epi16(f1, g1, 0xAA);
        f0 = _mm256_and_si256(f0, mask);
        f1 = _mm256_and_si256(f1, mask);
        pos += 48;

        g0 = _mm256_cmpgt_epi16(bound, f0);
        g1 = _mm256_cmpgt_epi16(bound, f1);
        g0 = _mm256_packs_epi16(g0, g1);
        good = _mm256_movemask_epi8(g0);
        g0 = _mm256_castsi128_si256(_mm_loadl_epi64(reinterpret_cast<const __m128i*>(&KYBER_REJ_IDX[good & 0xFF])));
        g1 = _mm256_castsi128_si256(_mm_loadl_epi64(reinterpret_cast<const __m128i*>(&KYBER_REJ_IDX[(good >> 8) & 0xFF])));
        g0 = _mm256_inserti128_si256(g0, _mm_loadl_epi64(reinterpret_cast<const __m128i*>(&KYBER_REJ_IDX[(good >> 16) & 0xFF])), 1);
        g1 = _mm256_inserti128_si256(g1, _mm_loadl_epi64(reinterpret_cast<const __m128i*>(&KYBER_REJ_IDX[(good >> 24) & 0xFF])), 1);
        g2 = _mm256_add_epi8(g0, ones);
        g3 = _mm256_add_epi8(g1, ones);
        g0 = _mm256_unpacklo_epi8(g0, g2);
        g1 = _mm256_unpacklo_epi8(g1, g3);
        f0 = _mm256_shuffle_epi8(f0, g0);
        f1 = _mm256_shuffle_epi8(f1, g1);

        _mm_storeu_si128(reinterpret_cast<__m128i*>(&pr[ctr]), _mm256_castsi256_si128(f0));
        ctr += _mm_popcnt_u32(good & 0xFF);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&pr[ctr]), _mm256_extracti128_si256(f0, 1));
        ctr += _mm_popcnt_u32((good >> 16) & 0xFF);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&pr[ctr]), _mm256_castsi256_si128(f1));
        ctr += _mm_popcnt_u32((good >> 8) & 0xFF);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&pr[ctr]), _mm256_extracti128_si256(f1, 1));
        ctr += _mm_popcnt_u32((good >> 24) & 0xFF);
    }

    while (ctr <= KYBER_N - 8 && pos <= AVX_REJ_UNIFORM_BUFLEN - 12)
    {
        f = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&pbuff[pos]));
        f = _mm_shuffle_epi8(f, _mm256_castsi256_si128(idx8));
        t = _mm_srli_epi16(f, 4);
        f = _mm_blend_epi16(f, t, 0xAA);
        f = _mm_and_si128(f, _mm256_castsi256_si128(mask));
        pos += 12;
        t = _mm_cmpgt_epi16(_mm256_castsi256_si128(bound), f);
        good = _mm_movemask_epi8(t);
        good = _pext_u32(good, 0x5555);
        pilo = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(&KYBER_REJ_IDX[good]));
        pihi = _mm_add_epi8(pilo, _mm256_castsi256_si128(ones));
        pilo = _mm_unpacklo_epi8(pilo, pihi);
        f = _mm_shuffle_epi8(f, pilo);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&pr[ctr]), f);
        ctr += _mm_popcnt_u32(good);
    }

    while (ctr < KYBER_N && pos <= AVX_REJ_UNIFORM_BUFLEN - 3)
    {
        val0 = (uint16_t)(((uint16_t)Buf[pos] | ((uint16_t)Buf[pos + 1] << 8)) & 0x0FFF);
        val1 = (uint16_t)(((uint16_t)Buf[pos + 1] >> 4) | ((uint16_t)Buf[pos + 2] << 4));
        pos += 3;

        if (val0 < KYBER_Q)
        {
            R.coeffs[ctr] = val0;
            ++ctr;
        }

        if (val1 < KYBER_Q && ctr < KYBER_N)
        {
            R.coeffs[ctr] = val1;
            ++ctr;
        }
    }

    return ctr;
}

void KyberBase::GenMatrix(std::vector<PolyVec> &A, const std::vector<uint8_t> &Seed, int32_t transposed, uint32_t K)
{
    const size_t VLEN = (K == 5) ? 5 : 4;
    std::array<__m256i, 25> ksa = { 0 };
    std::array<uint64_t, 25> state = { 0 };
    CEX_ALIGN(32) std::vector<std::vector<uint8_t>> buf(VLEN);
    CEX_ALIGN(32) std::vector<std::vector<uint8_t>> extseed(VLEN);
    std::vector<uint32_t> ctr(K);
    size_t i;
    size_t j;
    bool bchk;

    for (i = 0; i < VLEN; ++i)
    {
        buf[i].resize(GEN_MATRIX_NBLOCKS * Keccak::KECCAK128_RATE_SIZE + 2, 0x00);
        extseed[i].resize(KYBER_SYMBYTES + 2, 0x00);

        if (i < K)
        {
            MemoryTools::Copy(Seed, 0, extseed[i], 0, KYBER_SYMBYTES);
        }
    }

    for (i = 0; i < K; ++i)
    {
        for (j = 0; j < K; ++j)
        {
            if (transposed != 0)
            {
                extseed[j][KYBER_SYMBYTES] = (uint8_t)i;
                extseed[j][KYBER_SYMBYTES + 1] = (uint8_t)j;
            }
            else
            {
                extseed[j][KYBER_SYMBYTES] = (uint8_t)j;
                extseed[j][KYBER_SYMBYTES + 1] = (uint8_t)i;
            }
        }

        Keccak::AbsorbR24x1600H(ksa, Keccak::KECCAK128_RATE_SIZE, extseed[0], extseed[1], extseed[2], extseed[3], extseed[0].size(), Keccak::KECCAK_SHAKE_DOMAIN);
        Keccak::SqueezeBlocksR24x1600H(ksa, Keccak::KECCAK128_RATE_SIZE, buf[0], buf[1], buf[2], buf[3], GEN_MATRIX_NBLOCKS);

        if (K == 5)
        {
            Keccak::Absorb(extseed[4], 0, extseed[4].size(), Keccak::KECCAK128_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, state);
            Keccak::Squeeze(state, buf[4], 0, GEN_MATRIX_NBLOCKS, Keccak::KECCAK128_RATE_SIZE);
        }

        bchk = false;

        for (j = 0; j < K; ++j)
        {
            ctr[j] = RejUniformAvx2(A[i].vec[j], buf[j]);

            if (ctr[j] < KYBER_N)
            {
                bchk = true;
            }
        }

        while (bchk == true)
        {
            Keccak::SqueezeBlocksR24x1600H(ksa, Keccak::KECCAK128_RATE_SIZE, buf[0], buf[1], buf[2], buf[3], 1);

            if (K == 5)
            {
                Keccak::Squeeze(state, buf[4], 0, 1, Keccak::KECCAK128_RATE_SIZE);
            }

            bchk = false;

            for (j = 0; j < K; ++j)
            {
                if (ctr[j] < KYBER_N)
                {
                    ctr[j] += RejUniform(A[i].vec[j], ctr[j], KYBER_N - ctr[j], buf[j], Keccak::KECCAK128_RATE_SIZE);

                    if (ctr[j] < KYBER_N)
                    {
                        bchk = true;
                    }
                }
            }
        }

        MemoryTools::Clear(state, 0, state.size() * sizeof(uint64_t));
        MemoryTools::Clear(ksa, 0, ksa.size() * sizeof(__m256i));
    }
}

void KyberBase::CmovAvx2(std::vector<uint8_t> &R, const std::vector<uint8_t> &X, size_t XOffset, size_t Length, uint8_t B)
{
    __m256i xvec;
    __m256i rvec;
    __m256i bvec;
    size_t pos;
    uint8_t* pr = R.data();
    const uint8_t* px = X.data() + XOffset;

    B = -B;
    bvec = _mm256_set1_epi8(B);

    for (pos = 0; pos + 32 <= Length; pos += 32)
    {
        rvec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&pr[pos]));
        xvec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&px[pos]));
        xvec = _mm256_xor_si256(xvec, rvec);
        xvec = _mm256_and_si256(xvec, bvec);
        rvec = _mm256_xor_si256(rvec, xvec);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&pr[pos]), rvec);
    }

    while (pos < Length)
    {
        R[pos] ^= B & (X[pos] ^ R[pos]);
        pos += 1;
    }
}

int32_t KyberBase::VerifyAvx2(const std::vector<uint8_t> &A, const std::vector<uint8_t> &B, size_t Length)
{
    __m256i avec;
    __m256i bvec;
    __m256i cvec;
    uint64_t r;
    size_t pos;
    const uint8_t* pa = A.data();
    const uint8_t* pb = B.data();

    cvec = _mm256_setzero_si256();

    for (pos = 0; pos + 32 <= Length; pos += 32)
    {
        avec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&pa[pos]));
        bvec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&pb[pos]));
        avec = _mm256_xor_si256(avec, bvec);
        cvec = _mm256_or_si256(cvec, avec);
    }

    r = 1ULL - _mm256_testz_si256(cvec, cvec);

    if (pos < Length)
    {
        avec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&pa[pos]));
        bvec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&pb[pos]));
        cvec = _mm256_cmpeq_epi8(avec, bvec);
        r |= _mm256_movemask_epi8(cvec) & (static_cast<uint32_t>(-1L) >> (32 + pos - Length));
    }

    r = static_cast<uint64_t>((-static_cast<int64_t>(r)) >> 63);

    return static_cast<uint32_t>(r);
}

#else

void KyberBase::Cbd2(Poly& R, const std::vector<uint8_t>& Buf)
{
    uint32_t t;
    uint32_t d;
    int16_t a;
    int16_t b;

    for (size_t i = 0; i < R.coeffs.size() / 8; ++i)
    {
        t = IntegerTools::LeBytesTo32(Buf, 4 * i);
        d = t & 0x55555555UL;
        d += (t >> 1) & 0x55555555UL;

        for (size_t j = 0; j < 8; ++j)
        {
            a = static_cast<int16_t>((d >> (4 * j)) & 0x03);
            b = static_cast<int16_t>((d >> ((4 * j) + 2)) & 0x03);
            R.coeffs[(8 * i) + j] = a - b;
        }
    }
}

uint32_t KyberBase::LoadLe24(const std::vector<uint8_t> &X, size_t XOffset)
{
    uint32_t r;

    r = (uint32_t)X[XOffset];
    r |= (uint32_t)X[XOffset + 1] << 8;
    r |= (uint32_t)X[XOffset + 2] << 16;

    return r;
}

void KyberBase::Cbd3(Poly &R, const std::vector<uint8_t> &Buf)
{
    size_t i;
    size_t j;
    uint32_t t;
    uint32_t d;
    int16_t a;
    int16_t b;

    for (i = 0; i < R.coeffs.size() / 4; ++i)
    {
        t = LoadLe24(Buf, 3 * i);
        d = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for (j = 0; j < 4; ++j)
        {
            a = (d >> (6 * j + 0)) & 0x7;
            b = (d >> (6 * j + 3)) & 0x7;
            R.coeffs[4 * i + j] = a - b;
        }
    }
}

void KyberBase::PolyCompress(std::vector<uint8_t>& R, size_t ROffset, const Poly& A, uint32_t K)
{
    uint8_t t[8];
    size_t idx;
    int16_t u;

    idx = 0;

    if (K == 2 || K == 3)
    {
        for (size_t i = 0; i < A.coeffs.size() / 8; ++i)
        {
            for (size_t j = 0; j < 8; ++j)
            {
                // map to positive standard representatives
                u = A.coeffs[(8 * i) + j];
                u += (u >> 15) & KYBER_Q;
                t[j] = static_cast<uint8_t>((((static_cast<uint16_t>(u) << 4) + KYBER_Q / 2) / KYBER_Q) & 0x000F);
            }

            R[ROffset + idx] = static_cast<uint8_t>(t[0] | (t[1] << 4));
            ++idx;
            R[ROffset + idx] = static_cast<uint8_t>(t[2] | (t[3] << 4));
            ++idx;
            R[ROffset + idx] = static_cast<uint8_t>(t[4] | (t[5] << 4));
            ++idx;
            R[ROffset + idx] = static_cast<uint8_t>(t[6] | (t[7] << 4));
            ++idx;
        }
    }
    else
    {
        for (size_t i = 0; i < A.coeffs.size() / 8; ++i)
        {
            for (size_t j = 0; j < 8; ++j)
            {
                // map to positive standard representatives
                u = A.coeffs[(8 * i) + j];
                u += (u >> 15) & KYBER_Q;
                t[j] = (((static_cast<uint32_t>(u) << 5) + KYBER_Q / 2) / KYBER_Q) & 31;
            }

            R[ROffset + idx] = static_cast<uint8_t>(t[0] | (t[1] << 5));
            ++idx;
            R[ROffset + idx] = static_cast<uint8_t>((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
            ++idx;
            R[ROffset + idx] = static_cast<uint8_t>((t[3] >> 1) | (t[4] << 4));
            ++idx;
            R[ROffset + idx] = static_cast<uint8_t>((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
            ++idx;
            R[ROffset + idx] = static_cast<uint8_t>((t[6] >> 2) | (t[7] << 3));
            ++idx;
        }
    }
}

void KyberBase::GenMatrix(std::vector<PolyVec> &A, const std::vector<uint8_t> &Seed, int32_t Transposed, uint32_t K)
{
    std::vector<uint64_t> state(25, 0);
    std::vector<uint8_t> buf(GEN_MATRIX_NBLOCKS * Keccak::KECCAK128_RATE_SIZE + 2);
    std::vector<uint8_t> extseed(KYBER_SYMBYTES + 2);
    uint32_t buflen;
    uint32_t ctr;
    uint32_t off;

    MemoryTools::Copy(Seed, 0, extseed, 0, KYBER_SYMBYTES);

    for (size_t i = 0; i < K; ++i)
    {
        for (size_t j = 0; j < K; ++j)
        {
            if (Transposed != 0)
            {
                extseed[KYBER_SYMBYTES] = (uint8_t)i;
                extseed[KYBER_SYMBYTES + 1] = (uint8_t)j;
            }
            else
            {
                extseed[KYBER_SYMBYTES] = (uint8_t)j;
                extseed[KYBER_SYMBYTES + 1] = (uint8_t)i;
            }

            Keccak::Absorb(extseed, 0, extseed.size(), Keccak::KECCAK128_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, state);
            Keccak::Squeeze(state, buf, 0, GEN_MATRIX_NBLOCKS, Keccak::KECCAK128_RATE_SIZE);

            buflen = GEN_MATRIX_NBLOCKS * Keccak::KECCAK128_RATE_SIZE;
            ctr = RejUniform(A[i].vec[j], 0, KYBER_N, buf, buflen);

            while (ctr < KYBER_N)
            {
                off = buflen % 3;

                for (size_t k = 0; k < off; ++k)
                {
                    buf[k] = buf[buflen - off + k];
                }

                Keccak::Squeeze(state, buf, off, 1, Keccak::KECCAK1024_RATE_SIZE);
                buflen = off + Keccak::KECCAK128_RATE_SIZE;
                ctr += RejUniform(A[i].vec[j], ctr, KYBER_N - ctr, buf, buflen);
            }

            MemoryTools::Clear(state, 0, state.size() * sizeof(uint64_t));
        }
    }
}

void KyberBase::PolyDecompress(Poly& R, const std::vector<uint8_t>& A, size_t AOffset, uint32_t K)
{
    if (K == 2 || K == 3)
    {
        for (size_t i = 0; i < R.coeffs.size() / 2; ++i)
        {
            R.coeffs[2 * i] = static_cast<int16_t>(((static_cast<uint16_t>(A[AOffset] & 15) * KYBER_Q) + 8) >> 4);
            R.coeffs[(2 * i) + 1] = static_cast<int16_t>(((static_cast<uint16_t>(A[AOffset] >> 4) * KYBER_Q) + 8) >> 4);
            AOffset += 1;
        }
    }
    else
    {
        std::array<uint8_t, 8> t;

        for (size_t i = 0; i < R.coeffs.size() / 8; ++i)
        {
            t[0] = static_cast<uint8_t>(A[AOffset]);
            t[1] = static_cast<uint8_t>((A[AOffset] >> 5) | (A[AOffset + 1] << 3));
            t[2] = static_cast<uint8_t>(A[AOffset + 1] >> 2);
            t[3] = static_cast<uint8_t>((A[AOffset + 1] >> 7) | (A[AOffset + 2] << 1));
            t[4] = static_cast<uint8_t>((A[AOffset + 2] >> 4) | (A[AOffset + 3] << 4));
            t[5] = static_cast<uint8_t>(A[AOffset + 3] >> 1);
            t[6] = static_cast<uint8_t>((A[AOffset + 3] >> 6) | (A[AOffset + 4] << 2));
            t[7] = static_cast<uint8_t>(A[AOffset + 4] >> 3);
            AOffset += 5;

            for (size_t j = 0; j < 8; ++j)
            {
                R.coeffs[(8 * i) + j] = static_cast<uint16_t>((static_cast<uint32_t>(t[j] & 31) * KYBER_Q + 16) >> 5);
            }
        }
    }
}

void KyberBase::PolyVecDecompress(PolyVec& R, const std::vector<uint8_t>& A)
{
    size_t idx;

    idx = 0;

    if (R.vec.size() == 4 || R.vec.size() == 5)
    {
        std::array<uint16_t, 8> t;

        for (size_t i = 0; i < R.vec.size(); ++i)
        {
            for (size_t j = 0; j < KYBER_N / 8; ++j)
            {
                t[0] = static_cast<uint16_t>(A[idx]) | static_cast<uint16_t>(A[idx + 1] << 8);
                t[1] = static_cast<uint16_t>(A[idx + 1] >> 3) | static_cast<uint16_t>(A[idx + 2] << 5);
                t[2] = static_cast<uint16_t>(A[idx + 2] >> 6) | static_cast<uint16_t>(A[idx + 3] << 2) | static_cast<uint16_t>(A[idx + 4] << 10);
                t[3] = static_cast<uint16_t>(A[idx + 4] >> 1) | static_cast<uint16_t>(A[idx + 5] << 7);
                t[4] = static_cast<uint16_t>(A[idx + 5] >> 4) | static_cast<uint16_t>(A[idx + 6] << 4);
                t[5] = static_cast<uint16_t>(A[idx + 6] >> 7) | static_cast<uint16_t>(A[idx + 7] << 1) | static_cast<uint16_t>(A[idx + 8] << 9);
                t[6] = static_cast<uint16_t>(A[idx + 8] >> 2) | static_cast<uint16_t>(A[idx + 9] << 6);
                t[7] = static_cast<uint16_t>(A[idx + 9] >> 5) | static_cast<uint16_t>(A[idx + 10] << 3);
                idx += 11;

                for (size_t k = 0; k < 8; ++k)
                {
                    R.vec[i].coeffs[(8 * j) + k] = static_cast<int16_t>((static_cast<uint32_t>(t[k] & 0x7FF) * KYBER_Q + 1024) >> 11);
                }
            }
        }
    }
    else if (R.vec.size() == 2 || R.vec.size() == 3)
    {
        std::array<uint16_t, 4> t;

        for (size_t i = 0; i < R.vec.size(); ++i)
        {
            for (size_t j = 0; j < KYBER_N / 4; ++j)
            {
                t[0] = static_cast<uint16_t>(A[idx] | (static_cast<uint16_t>(A[idx + 1]) << 8));
                t[1] = static_cast<uint16_t>((A[idx + 1] >> 2) | (static_cast<uint16_t>(A[idx + 2]) << 6));
                t[2] = static_cast<uint16_t>((A[idx + 2] >> 4) | (static_cast<uint16_t>(A[idx + 3]) << 4));
                t[3] = static_cast<uint16_t>((A[idx + 3] >> 6) | (static_cast<uint16_t>(A[idx + 4]) << 2));
                idx += 5;

                for (size_t k = 0; k < 4; ++k)
                {
                    R.vec[i].coeffs[(4 * j) + k] = static_cast<int16_t>(((static_cast<uint32_t>(t[k] & 0x3FF) * KYBER_Q) + 512) >> 10);
                }
            }
        }
    }
}

void KyberBase::PolyFromMsg(Poly& R, const std::vector<uint8_t>& Msg)
{
    int16_t mask;

    for (size_t i = 0; i < R.coeffs.size() / 8; ++i)
    {
        for (size_t j = 0; j < 8; ++j)
        {
            mask = -static_cast<int16_t>((Msg[i] >> j) & 1);
            R.coeffs[(8 * i) + j] = mask & (static_cast<int16_t>(KYBER_Q + 1) / 2);
        }
    }
}

void KyberBase::PolyAdd(Poly& R, const Poly& A, const Poly& B)
{
    for (size_t i = 0; i < R.coeffs.size(); ++i)
    {
        R.coeffs[i] = A.coeffs[i] + B.coeffs[i];
    }
}

void KyberBase::PolySub(Poly& R, const Poly& A, const Poly& B)
{
    for (size_t i = 0; i < R.coeffs.size(); ++i)
    {
        R.coeffs[i] = A.coeffs[i] - B.coeffs[i];
    }
}

#endif

NAMESPACE_KYBEREND