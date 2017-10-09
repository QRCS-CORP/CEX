#define CRYPTO_SECRETKEYBYTES 5984
#define CRYPTO_PUBLICKEYBYTES 311736
#define CRYPTO_BYTES 109

#define CRYPTO_VERSION "1.0"
#ifndef _CEX_FFTM12T62_H
#define _CEX_FFTM12T62_H


/*
// new
#include "CexDomain.h"
#include "GoppaField.h"
#include "GoppaUtils.h"
#include "IAeadMode.h"
#include "IDigest.h"
#include "IntUtils.h"
#include "IPrng.h"
#include "MemUtils.h"
#include "SymmetricKey.h"

NAMESPACE_MCELIECE

using Cipher::Symmetric::Block::Mode::IAeadMode;
using Digest::IDigest;
using Utility::IntUtils;
using Prng::IPrng;
using Utility::MemUtils;


/// <summary>
/// The McEliece M12T62 FFT
/// </summary>
class FFTM12T62
{
private:

	static const ulong ButterflyConsts[63][12];
	static const byte ButterflyReverse[64];
	static const ulong GfPoints[64][12];
	static const ulong RadixMask[5][2];
	static const ulong RadixScalar[5][12];

public:

	static const size_t M = 12;
	static const size_t T = 62;
	static const size_t PKN_ROWS = (T * M);
	static const size_t PKN_COLS = ((1 << M) - T * M);
	static const size_t IRR_SZE = (M * 8);
	static const size_t CND_SZE = (736 * 8);
	static const size_t SND_SZE = (PKN_ROWS / 8);
	static const size_t GEN_MAXR = 100;

	static int Decrypt(std::vector<byte> &E, const std::vector<byte> &PrivateKey, const std::vector<byte> &S)
	{
		size_t i;
		ulong t;
		ulong diff;
		std::vector<ulong> error(64);
		std::vector<ulong> locator(M);
		std::vector<ulong> recv(64);
		std::vector<ulong> cond(CND_SZE / 8);
		ulong inverse[64][M];
		ulong scaled[64][M];
		ulong eval[64][M];
		ulong sPriv[2][M];
		ulong sPrivCmp[2][M];

		IntUtils::BlockToLe<ulong>(PrivateKey, IRR_SZE, cond, 0, CND_SZE);
		PreProcess(recv, S);
		GoppaUtils::BenesCompact(recv.data(), cond.data(), 1);
		// scaling
		Scaling(scaled, inverse, PrivateKey, recv);
		// transposed FFT
		TransposedFFT::Transform(sPriv, scaled);
		SyndromeAdjust(sPriv);
		// Berlekamp Massey
		BerlekampMassey(locator, sPriv);
		// additive FFT
		AdditiveFFT::Transform(eval, locator.data());

		for (i = 0; i < 64; i++)
		{
			error[i] = GoppaField::Or(eval[i], M);
			error[i] = ~error[i];
		}

		// re-encrypt
		ScalingInverse(scaled, inverse, error);
		TransposedFFT::Transform(sPrivCmp, scaled);
		SyndromeAdjust(sPrivCmp);

		diff = 0;
		diff |= sPriv[0][0] ^ sPrivCmp[0][0];
		diff |= sPriv[0][1] ^ sPrivCmp[0][1];
		diff |= sPriv[0][2] ^ sPrivCmp[0][2];
		diff |= sPriv[0][3] ^ sPrivCmp[0][3];
		diff |= sPriv[0][4] ^ sPrivCmp[0][4];
		diff |= sPriv[0][5] ^ sPrivCmp[0][5];
		diff |= sPriv[0][6] ^ sPrivCmp[0][6];
		diff |= sPriv[0][7] ^ sPrivCmp[0][7];
		diff |= sPriv[0][8] ^ sPrivCmp[0][8];
		diff |= sPriv[0][9] ^ sPrivCmp[0][9];
		diff |= sPriv[0][10] ^ sPrivCmp[0][10];
		diff |= sPriv[0][11] ^ sPrivCmp[0][11];
		diff |= sPriv[1][0] ^ sPrivCmp[1][0];
		diff |= sPriv[1][1] ^ sPrivCmp[1][1];
		diff |= sPriv[1][2] ^ sPrivCmp[1][2];
		diff |= sPriv[1][3] ^ sPrivCmp[1][3];
		diff |= sPriv[1][4] ^ sPrivCmp[1][4];
		diff |= sPriv[1][5] ^ sPrivCmp[1][5];
		diff |= sPriv[1][6] ^ sPrivCmp[1][6];
		diff |= sPriv[1][7] ^ sPrivCmp[1][7];
		diff |= sPriv[1][8] ^ sPrivCmp[1][8];
		diff |= sPriv[1][9] ^ sPrivCmp[1][9];
		diff |= sPriv[1][10] ^ sPrivCmp[1][10];
		diff |= sPriv[1][11] ^ sPrivCmp[1][11];
		diff |= diff >> 32;
		diff |= diff >> 16;
		diff |= diff >> 8;
		t = diff & 0xFF;

		// compact and store
		GoppaUtils::BenesCompact(error.data(), cond.data(), 0);
		IntUtils::LeToBlock<ulong>(error, 0, E, 0, error.size() * sizeof(ulong));

		t |= GoppaUtils::Weight(error.data()) ^ T;
		t -= 1;
		t >>= 63;

		return (t - 1);
	}

	static void Encrypt(std::vector<byte> &S, std::vector<byte> &E, const std::vector<byte> &PublicKey, IPrng* Random)
	{
		GenE(E, Random);
		Syndrome(S, PublicKey, E);
	}

	static int Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, IPrng* Random)
	{
		size_t ctr;

		for (ctr = 0; ctr < GEN_MAXR; ++ctr)
		{
			SkGen(PrivateKey, Random);

			if (PkGen(PublicKey, PrivateKey) == 0)
				break;
		}

		return (ctr < GEN_MAXR) ? 0 : -1;
	}

private:

	//~~~Decrypt~~~//

	static void BerlekampMassey(std::vector<ulong> &Output, ulong Input[][M])
	{
		ushort N;
		ushort L;
		ushort mask16b;
		ushort d;
		ushort b;
		ushort bInv;
		ushort r;
		ulong maskNz;
		ulong maskLeq;
		ulong B[M];
		ulong prod[M];
		ulong tmpIn[M];
		ulong rVec[M];
		ulong tmpC[M];

		Output[0] = 1;
		std::memcpy(&B[0], &Output[0], M * sizeof(ulong));
		Output[0] <<= 63;
		B[0] <<= 62;
		b = 1;
		L = 0;

		for (N = 0; N < T * 2; N++)
		{
			// computing d
			if (N < 64)
			{
				tmpIn[0] = Input[0][0] << (63 - N);
				tmpIn[1] = Input[0][1] << (63 - N);
				tmpIn[2] = Input[0][2] << (63 - N);
				tmpIn[3] = Input[0][3] << (63 - N);
				tmpIn[4] = Input[0][4] << (63 - N);
				tmpIn[5] = Input[0][5] << (63 - N);
				tmpIn[6] = Input[0][6] << (63 - N);
				tmpIn[7] = Input[0][7] << (63 - N);
				tmpIn[8] = Input[0][8] << (63 - N);
				tmpIn[9] = Input[0][9] << (63 - N);
				tmpIn[10] = Input[0][10] << (63 - N);
				tmpIn[11] = Input[0][11] << (63 - N);
			}
			else
			{
				tmpIn[0] = (Input[0][0] >> (N - 63)) | (Input[1][0] << (127 - N));
				tmpIn[1] = (Input[0][1] >> (N - 63)) | (Input[1][1] << (127 - N));
				tmpIn[2] = (Input[0][2] >> (N - 63)) | (Input[1][2] << (127 - N));
				tmpIn[3] = (Input[0][3] >> (N - 63)) | (Input[1][3] << (127 - N));
				tmpIn[4] = (Input[0][4] >> (N - 63)) | (Input[1][4] << (127 - N));
				tmpIn[5] = (Input[0][5] >> (N - 63)) | (Input[1][5] << (127 - N));
				tmpIn[6] = (Input[0][6] >> (N - 63)) | (Input[1][6] << (127 - N));
				tmpIn[7] = (Input[0][7] >> (N - 63)) | (Input[1][7] << (127 - N));
				tmpIn[8] = (Input[0][8] >> (N - 63)) | (Input[1][8] << (127 - N));
				tmpIn[9] = (Input[0][9] >> (N - 63)) | (Input[1][9] << (127 - N));
				tmpIn[10] = (Input[0][10] >> (N - 63)) | (Input[1][10] << (127 - N));
				tmpIn[11] = (Input[0][11] >> (N - 63)) | (Input[1][11] << (127 - N));
			}

			GoppaMath::Multiply(prod, Output.data(), tmpIn);
			d = GoppaUtils::Reduce(prod, M);

			// 3 cases
			bInv = GoppaField::Invert(b, M);
			r = GoppaField::Multiply(d, bInv, M);
			GoppaUtils::Insert(rVec, r, M);
			GoppaMath::Multiply(tmpC, rVec, B);

			tmpC[0] ^= Output[0];
			tmpC[1] ^= Output[1];
			tmpC[2] ^= Output[2];
			tmpC[3] ^= Output[3];
			tmpC[4] ^= Output[4];
			tmpC[5] ^= Output[5];
			tmpC[6] ^= Output[6];
			tmpC[7] ^= Output[7];
			tmpC[8] ^= Output[8];
			tmpC[9] ^= Output[9];
			tmpC[10] ^= Output[10];
			tmpC[11] ^= Output[11];

			maskNz = GoppaUtils::MaskNonZero64(d);
			maskLeq = GoppaUtils::MaskLeq64(L * 2, N);
			mask16b = (maskNz & maskLeq) & 0xFFFF;

			GoppaUtils::CMov(B, Output.data(), maskNz & maskLeq, M);
			GoppaField::Copy(Output.data(), tmpC, M);

			b = (d & mask16b) | (b & ~mask16b);
			L = ((N + 1 - L) & mask16b) | (L & ~mask16b);

			B[0] >>= 1;
			B[1] >>= 1;
			B[2] >>= 1;
			B[3] >>= 1;
			B[4] >>= 1;
			B[5] >>= 1;
			B[6] >>= 1;
			B[7] >>= 1;
			B[8] >>= 1;
			B[9] >>= 1;
			B[10] >>= 1;
			B[11] >>= 1;
		}

		Output[0] >>= 64 - (T + 1);
		Output[1] >>= 64 - (T + 1);
		Output[2] >>= 64 - (T + 1);
		Output[3] >>= 64 - (T + 1);
		Output[4] >>= 64 - (T + 1);
		Output[5] >>= 64 - (T + 1);
		Output[6] >>= 64 - (T + 1);
		Output[7] >>= 64 - (T + 1);
		Output[8] >>= 64 - (T + 1);
		Output[9] >>= 64 - (T + 1);
		Output[10] >>= 64 - (T + 1);
		Output[11] >>= 64 - (T + 1);
	}

	static void PreProcess(std::vector<ulong> &Received, const std::vector<byte> &S)
	{
		IntUtils::BlockToLe<ulong>(S, 0, Received, 0, SND_SZE - 5);
		Received[11] <<= 8;
		Received[11] |= S[92];
		Received[11] <<= 8;
		Received[11] |= S[91];
		Received[11] <<= 8;
		Received[11] |= S[90];
		Received[11] <<= 8;
		Received[11] |= S[89];
		Received[11] <<= 8;
		Received[11] |= S[88];
	}

	static void Scaling(ulong Output[][M], ulong Inverse[][M], const std::vector<byte> &PrivateKey, std::vector<ulong> &Received)
	{
		size_t i;
		ulong skInt[M];
		ulong eval[64][M];
		ulong tmp[M];

		// computing inverses
		std::memcpy(&skInt[0], &PrivateKey[0], M * sizeof(ulong));
		AdditiveFFT::Transform(eval, skInt);
		GoppaMath::Square(eval[0], eval[0]);
		GoppaField::Copy(Inverse[0], eval[0], M);

		for (i = 1; i < 64; i++) // TODO: unroll?
		{
			GoppaMath::Square(eval[i], eval[i]);
			GoppaMath::Multiply(Inverse[i], Inverse[i - 1], eval[i]);
		}

		GoppaMath::Invert(tmp, Inverse[63]);

		i = 63;
		while (i--) // TODO: unroll?
		{
			GoppaMath::Multiply(Inverse[i + 1], tmp, Inverse[i]);
			GoppaMath::Multiply(tmp, tmp, eval[i + 1]);
		}
		GoppaField::Copy(Inverse[0], tmp, M);

		for (i = 0; i < 64; i++)
		{
			Output[i][0] = Inverse[i][0] & Received[i];
			Output[i][1] = Inverse[i][1] & Received[i];
			Output[i][2] = Inverse[i][2] & Received[i];
			Output[i][3] = Inverse[i][3] & Received[i];
			Output[i][4] = Inverse[i][4] & Received[i];
			Output[i][5] = Inverse[i][5] & Received[i];
			Output[i][6] = Inverse[i][6] & Received[i];
			Output[i][7] = Inverse[i][7] & Received[i];
			Output[i][8] = Inverse[i][8] & Received[i];
			Output[i][9] = Inverse[i][9] & Received[i];
			Output[i][10] = Inverse[i][10] & Received[i];
			Output[i][11] = Inverse[i][11] & Received[i];
		}
	}

	static void ScalingInverse(ulong Output[][M], ulong Inverse[][M], std::vector<ulong> &Received)
	{
		for (size_t i = 0; i < 64; i++)
		{
			Output[i][0] = Inverse[i][0] & Received[i];
			Output[i][1] = Inverse[i][1] & Received[i];
			Output[i][2] = Inverse[i][2] & Received[i];
			Output[i][3] = Inverse[i][3] & Received[i];
			Output[i][4] = Inverse[i][4] & Received[i];
			Output[i][5] = Inverse[i][5] & Received[i];
			Output[i][6] = Inverse[i][6] & Received[i];
			Output[i][7] = Inverse[i][7] & Received[i];
			Output[i][8] = Inverse[i][8] & Received[i];
			Output[i][9] = Inverse[i][9] & Received[i];
			Output[i][10] = Inverse[i][10] & Received[i];
			Output[i][11] = Inverse[i][11] & Received[i];
		}
	}

	static void SyndromeAdjust(ulong Input[][M])
	{
		Input[1][0] <<= (128 - T * 2);
		Input[1][0] >>= (128 - T * 2);
		Input[1][1] <<= (128 - T * 2);
		Input[1][1] >>= (128 - T * 2);
		Input[1][2] <<= (128 - T * 2);
		Input[1][2] >>= (128 - T * 2);
		Input[1][3] <<= (128 - T * 2);
		Input[1][3] >>= (128 - T * 2);
		Input[1][4] <<= (128 - T * 2);
		Input[1][4] >>= (128 - T * 2);
		Input[1][5] <<= (128 - T * 2);
		Input[1][5] >>= (128 - T * 2);
		Input[1][6] <<= (128 - T * 2);
		Input[1][6] >>= (128 - T * 2);
		Input[1][7] <<= (128 - T * 2);
		Input[1][7] >>= (128 - T * 2);
		Input[1][8] <<= (128 - T * 2);
		Input[1][8] >>= (128 - T * 2);
		Input[1][9] <<= (128 - T * 2);
		Input[1][9] >>= (128 - T * 2);
		Input[1][10] <<= (128 - T * 2);
		Input[1][10] >>= (128 - T * 2);
		Input[1][11] <<= (128 - T * 2);
		Input[1][11] >>= (128 - T * 2);
	}

	//~~~Encrypt~~~//

	static void GenE(std::vector<byte> &E, IPrng* Random)
	{
		size_t i;
		size_t j;
		size_t eq;
		ulong mask;
		std::vector<ushort> ind(T);
		std::vector<ulong> eInt(64, 0);
		std::vector<ulong> val(T);

		while (1)
		{
			Random->Fill(ind, 0, ind.size());

			for (i = 0; i < T; i++)
				ind[i] &= (1 << M) - 1;

			eq = 0;
			for (i = 1; i < T; i++)
			{
				for (j = 0; j < i; j++)
				{
					if (ind[i] == ind[j])
						eq = 1;
				}
			}

			if (eq == 0)
				break;
		}

		for (j = 0; j < T; j++)
			val[j] = (ulong)1 << (ind[j] & 63);

		for (i = 0; i < 64; i++)
		{
			for (j = 0; j < T; j++)
			{
				mask = i ^ (ind[j] >> 6);
				mask -= 1;
				mask >>= 63;
				mask = ~mask + 1;
				eInt[i] |= val[j] & mask;
			}
		}

		IntUtils::LeToBlock<ulong>(eInt, 0, E, 0, eInt.size() * sizeof(ulong));
	}

	static void Syndrome(std::vector<byte> &S, const std::vector<byte> &PublicKey, const std::vector<byte> &E)
	{
		const size_t CSZE = ((PKN_COLS + 63) / 64);
		const size_t COLSZE = PKN_COLS / 8;
		size_t t;
		byte b;
		std::vector<ulong> eInt(CSZE, 0);
		std::vector<ulong> rowInt(CSZE, 0);
		std::vector<ulong> tmp(8, 0);

		MemUtils::Copy<byte, ulong>(E, SND_SZE, eInt, 0, COLSZE);

		for (size_t i = 0; i < PKN_ROWS; i += 8)
		{
			for (t = 0; t < 8; t++)
			{
				MemUtils::Copy<byte, ulong>(PublicKey, (i + t) * COLSZE, rowInt, 0, COLSZE);
				tmp[t] = eInt[0] & rowInt[0];
				tmp[t] ^= eInt[1] & rowInt[1];
				tmp[t] ^= eInt[2] & rowInt[2];
				tmp[t] ^= eInt[3] & rowInt[3];
				tmp[t] ^= eInt[4] & rowInt[4];
				tmp[t] ^= eInt[5] & rowInt[5];
				tmp[t] ^= eInt[6] & rowInt[6];
				tmp[t] ^= eInt[7] & rowInt[7];
				tmp[t] ^= eInt[8] & rowInt[8];
				tmp[t] ^= eInt[9] & rowInt[9];
				tmp[t] ^= eInt[10] & rowInt[10];
				tmp[t] ^= eInt[11] & rowInt[11];
				tmp[t] ^= eInt[12] & rowInt[12];
				tmp[t] ^= eInt[13] & rowInt[13];
				tmp[t] ^= eInt[14] & rowInt[14];
				tmp[t] ^= eInt[15] & rowInt[15];
				tmp[t] ^= eInt[16] & rowInt[16];
				tmp[t] ^= eInt[17] & rowInt[17];
				tmp[t] ^= eInt[18] & rowInt[18];
				tmp[t] ^= eInt[19] & rowInt[19];
				tmp[t] ^= eInt[20] & rowInt[20];
				tmp[t] ^= eInt[21] & rowInt[21];
				tmp[t] ^= eInt[22] & rowInt[22];
				tmp[t] ^= eInt[23] & rowInt[23];
				tmp[t] ^= eInt[24] & rowInt[24];
				tmp[t] ^= eInt[25] & rowInt[25];
				tmp[t] ^= eInt[26] & rowInt[26];
				tmp[t] ^= eInt[27] & rowInt[27];
				tmp[t] ^= eInt[28] & rowInt[28];
				tmp[t] ^= eInt[29] & rowInt[29];
				tmp[t] ^= eInt[30] & rowInt[30];
				tmp[t] ^= eInt[31] & rowInt[31];
				tmp[t] ^= eInt[32] & rowInt[32];
				tmp[t] ^= eInt[33] & rowInt[33];
				tmp[t] ^= eInt[34] & rowInt[34];
				tmp[t] ^= eInt[35] & rowInt[35];
				tmp[t] ^= eInt[36] & rowInt[36];
				tmp[t] ^= eInt[37] & rowInt[37];
				tmp[t] ^= eInt[38] & rowInt[38];
				tmp[t] ^= eInt[39] & rowInt[39];
				tmp[t] ^= eInt[40] & rowInt[40];
				tmp[t] ^= eInt[41] & rowInt[41];
				tmp[t] ^= eInt[42] & rowInt[42];
				tmp[t] ^= eInt[43] & rowInt[43];
				tmp[t] ^= eInt[44] & rowInt[44];
				tmp[t] ^= eInt[45] & rowInt[45];
				tmp[t] ^= eInt[46] & rowInt[46];
				tmp[t] ^= eInt[47] & rowInt[47];
				tmp[t] ^= eInt[48] & rowInt[48];
				tmp[t] ^= eInt[49] & rowInt[49];
				tmp[t] ^= eInt[50] & rowInt[50];
				tmp[t] ^= eInt[51] & rowInt[51];
				tmp[t] ^= eInt[52] & rowInt[52];
			}

			tmp[7] ^= (tmp[7] >> 32);
			tmp[7] ^= (tmp[7] >> 16);
			tmp[7] ^= (tmp[7] >> 8);
			tmp[7] ^= (tmp[7] >> 4);
			b = (0x6996 >> (tmp[7] & 0xF)) & 1;
			tmp[6] ^= (tmp[6] >> 32);
			tmp[6] ^= (tmp[6] >> 16);
			tmp[6] ^= (tmp[6] >> 8);
			tmp[6] ^= (tmp[6] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[6] & 0xF)) & 1;
			tmp[5] ^= (tmp[5] >> 32);
			tmp[5] ^= (tmp[5] >> 16);
			tmp[5] ^= (tmp[5] >> 8);
			tmp[5] ^= (tmp[5] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[5] & 0xF)) & 1;
			tmp[4] ^= (tmp[4] >> 32);
			tmp[4] ^= (tmp[4] >> 16);
			tmp[4] ^= (tmp[4] >> 8);
			tmp[4] ^= (tmp[4] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[4] & 0xF)) & 1;
			tmp[3] ^= (tmp[3] >> 32);
			tmp[3] ^= (tmp[3] >> 16);
			tmp[3] ^= (tmp[3] >> 8);
			tmp[3] ^= (tmp[3] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[3] & 0xF)) & 1;
			tmp[2] ^= (tmp[2] >> 32);
			tmp[2] ^= (tmp[2] >> 16);
			tmp[2] ^= (tmp[2] >> 8);
			tmp[2] ^= (tmp[2] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[2] & 0xF)) & 1;
			tmp[1] ^= (tmp[1] >> 32);
			tmp[1] ^= (tmp[1] >> 16);
			tmp[1] ^= (tmp[1] >> 8);
			tmp[1] ^= (tmp[1] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[1] & 0xF)) & 1;
			tmp[0] ^= (tmp[0] >> 32);
			tmp[0] ^= (tmp[0] >> 16);
			tmp[0] ^= (tmp[0] >> 8);
			tmp[0] ^= (tmp[0] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[0] & 0xF)) & 1;

			S[i / 8] = E[i / 8] ^ b;
		}
	}

	//~~~KeyGen~~~//

	static int IrrGen(std::vector<ushort> &Output, std::vector<ushort> &F)
	{
		size_t i;
		size_t j;
		size_t k;
		size_t c;
		ushort mask;
		ushort inverse;
		ushort t;
		ushort mat[T + 1][T];

		// fill matrix
		mat[0][0] = 1;

		std::memset(&mat[0][1], 0, (T - 1) * sizeof(ushort));
		std::memcpy(&mat[1][1], &F[1], (T - 1) * sizeof(ushort));
		for (i = 1; i < T; i++)
		{
			mat[0][i] = 0;
			mat[1][i] = F[i];
		}

		for (j = 2; j <= T; j++)
			GoppaMath::Multiply(mat[j], mat[j - 1], F.data());

		// gaussian
		for (j = 0; j < T; j++)
		{
			for (k = j + 1; k < T; k++)
			{
				mask = GoppaField::Diff(mat[j][j], mat[j][k]);

				for (c = 0; c < T + 1; c++)
					mat[c][j] ^= mat[c][k] & mask;
			}

			// return if not invertible
			if (mat[j][j] == 0)
				return -1;

			// compute inverse
			inverse = GoppaField::Invert(mat[j][j], M);

			for (c = 0; c < T + 1; c++)
				mat[c][j] = GoppaField::Multiply(mat[c][j], inverse, M);

			for (k = 0; k < T; k++)
			{
				t = mat[j][k];

				if (k != j)
				{
					for (c = 0; c < T + 1; c++)
						mat[c][k] ^= GoppaField::Multiply(mat[c][j], t, M);
				}
			}
		}

		for (i = 0; i < T; i++)
			Output[i] = mat[T][i];

		Output[T] = 1;

		return 0;
	}

	static void SkGen(std::vector<byte> &PrivateKey, IPrng* Random)
	{
		size_t i;
		std::vector<ulong> cond(CND_SZE / 8);
		std::vector<ushort> f(T);
		std::vector<ulong> skInt(M, 0);
		std::vector<ushort> irr(T + 1);

		while (1)
		{
			Random->Fill(f, 0, f.size());

			for (i = 0; i < T; i++)
				f[i] &= (1 << M) - 1;

			if (IrrGen(irr, f) == 0)
				break;
		}

		for (i = 0; i < M; i++) // TODO: vectorize?
		{
			skInt[i] <<= 1;
			skInt[i] |= (irr[0] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[1] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[2] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[3] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[4] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[5] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[6] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[7] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[8] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[9] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[10] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[11] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[12] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[13] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[14] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[15] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[16] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[17] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[18] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[19] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[20] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[21] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[22] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[23] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[24] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[25] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[26] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[27] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[28] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[29] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[30] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[31] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[32] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[33] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[34] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[35] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[36] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[37] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[38] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[39] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[40] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[41] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[42] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[43] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[44] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[45] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[46] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[47] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[48] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[49] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[50] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[51] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[52] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[53] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[54] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[55] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[56] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[57] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[58] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[59] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[60] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[61] >> i) & 1;
			skInt[i] <<= 1;
			skInt[i] |= (irr[62] >> i) & 1;

			IntUtils::Le64ToBytes(skInt[i], PrivateKey, i * 8);
		}

		Random->Fill(cond, 0, cond.size());

		for (i = 0; i < CND_SZE / 8; i++)
			IntUtils::Le64ToBytes(cond[i], PrivateKey, IRR_SZE + i * 8);
	}

	static int PkGen(std::vector<byte> &PublicKey, const std::vector<byte> &PrivateKey)
	{
		size_t i;
		size_t j;
		size_t k;
		size_t row;
		size_t tail;
		ulong mask;
		ulong u;
		ulong mat[PKN_ROWS][64];
		ulong skInt[M];
		ulong eval[64][M];
		ulong inverse[64][M];
		ulong tmp[M];
		ulong cond[CND_SZE / 8];

		// compute the inverses
		for (i = 0; i < M; i++)
			skInt[i] = IntUtils::LeBytesTo64(PrivateKey, i * 8);

		AdditiveFFT::Transform(eval, skInt);
		GoppaField::Copy(inverse[0], eval[0], M);

		for (i = 1; i < 64; i++)
			GoppaMath::Multiply(inverse[i], inverse[i - 1], eval[i]);

		GoppaMath::Invert(tmp, inverse[63]);

		i = T + 1;
		while (i--)
		{
			GoppaMath::Multiply(inverse[i + 1], tmp, inverse[i]);
			GoppaMath::Multiply(tmp, tmp, eval[i + 1]);
		}

		GoppaField::Copy(inverse[0], tmp, M);

		// fill matrix 
		for (j = 0; j < 64; j++)
		{
			mat[0][j] = inverse[j][0];
			mat[1][j] = inverse[j][1];
			mat[2][j] = inverse[j][2];
			mat[3][j] = inverse[j][3];
			mat[4][j] = inverse[j][4];
			mat[5][j] = inverse[j][5];
			mat[6][j] = inverse[j][6];
			mat[7][j] = inverse[j][7];
			mat[8][j] = inverse[j][8];
			mat[9][j] = inverse[j][9];
			mat[10][j] = inverse[j][10];
			mat[11][j] = inverse[j][11];
		}

		for (i = 1; i < T; i++)
		{
			for (j = 0; j < 64; j++)
			{
				GoppaMath::Multiply(inverse[j], inverse[j], GfPoints[j]);
				mat[i * M][j] = inverse[j][0];
				mat[i * M + 1][j] = inverse[j][1];
				mat[i * M + 2][j] = inverse[j][2];
				mat[i * M + 3][j] = inverse[j][3];
				mat[i * M + 4][j] = inverse[j][4];
				mat[i * M + 5][j] = inverse[j][5];
				mat[i * M + 6][j] = inverse[j][6];
				mat[i * M + 7][j] = inverse[j][7];
				mat[i * M + 8][j] = inverse[j][8];
				mat[i * M + 9][j] = inverse[j][9];
				mat[i * M + 10][j] = inverse[j][10];
				mat[i * M + 11][j] = inverse[j][11];
			}
		}

		// permute 
		for (i = 0; i < CND_SZE / 8; i++)
			cond[i] = IntUtils::LeBytesTo64(PrivateKey, IRR_SZE + i * 8);


		for (i = 0; i < PKN_ROWS; i++)
			GoppaUtils::BenesCompact(mat[i], cond, 0);

		// gaussian elimination 
		for (i = 0; i < M; i++) // TODO: vectorize?
		{
			for (j = 0; j < 64; j++)
			{
				row = i * 64 + j;

				if (row >= PKN_ROWS)
					break;

				for (k = row + 1; k < PKN_ROWS; k++)
				{
					mask = mat[row][i] ^ mat[k][i];
					mask >>= j;
					mask &= 1;
					mask = ~mask + 1;
					mat[row][0] ^= mat[k][0] & mask;
					mat[row][1] ^= mat[k][1] & mask;
					mat[row][2] ^= mat[k][2] & mask;
					mat[row][3] ^= mat[k][3] & mask;
					mat[row][4] ^= mat[k][4] & mask;
					mat[row][5] ^= mat[k][5] & mask;
					mat[row][6] ^= mat[k][6] & mask;
					mat[row][7] ^= mat[k][7] & mask;
					mat[row][8] ^= mat[k][8] & mask;
					mat[row][9] ^= mat[k][9] & mask;
					mat[row][10] ^= mat[k][10] & mask;
					mat[row][11] ^= mat[k][11] & mask;
					mat[row][12] ^= mat[k][12] & mask;
					mat[row][13] ^= mat[k][13] & mask;
					mat[row][14] ^= mat[k][14] & mask;
					mat[row][15] ^= mat[k][15] & mask;
					mat[row][16] ^= mat[k][16] & mask;
					mat[row][17] ^= mat[k][17] & mask;
					mat[row][18] ^= mat[k][18] & mask;
					mat[row][19] ^= mat[k][19] & mask;
					mat[row][20] ^= mat[k][20] & mask;
					mat[row][21] ^= mat[k][21] & mask;
					mat[row][22] ^= mat[k][22] & mask;
					mat[row][23] ^= mat[k][23] & mask;
					mat[row][24] ^= mat[k][24] & mask;
					mat[row][25] ^= mat[k][25] & mask;
					mat[row][26] ^= mat[k][26] & mask;
					mat[row][27] ^= mat[k][27] & mask;
					mat[row][28] ^= mat[k][28] & mask;
					mat[row][29] ^= mat[k][29] & mask;
					mat[row][30] ^= mat[k][30] & mask;
					mat[row][31] ^= mat[k][31] & mask;
					mat[row][32] ^= mat[k][32] & mask;
					mat[row][33] ^= mat[k][33] & mask;
					mat[row][34] ^= mat[k][34] & mask;
					mat[row][35] ^= mat[k][35] & mask;
					mat[row][36] ^= mat[k][36] & mask;
					mat[row][37] ^= mat[k][37] & mask;
					mat[row][38] ^= mat[k][38] & mask;
					mat[row][39] ^= mat[k][39] & mask;
					mat[row][40] ^= mat[k][40] & mask;
					mat[row][41] ^= mat[k][41] & mask;
					mat[row][42] ^= mat[k][42] & mask;
					mat[row][43] ^= mat[k][43] & mask;
					mat[row][44] ^= mat[k][44] & mask;
					mat[row][45] ^= mat[k][45] & mask;
					mat[row][46] ^= mat[k][46] & mask;
					mat[row][47] ^= mat[k][47] & mask;
					mat[row][48] ^= mat[k][48] & mask;
					mat[row][49] ^= mat[k][49] & mask;
					mat[row][50] ^= mat[k][50] & mask;
					mat[row][51] ^= mat[k][51] & mask;
					mat[row][52] ^= mat[k][52] & mask;
					mat[row][53] ^= mat[k][53] & mask;
					mat[row][54] ^= mat[k][54] & mask;
					mat[row][55] ^= mat[k][55] & mask;
					mat[row][56] ^= mat[k][56] & mask;
					mat[row][57] ^= mat[k][57] & mask;
					mat[row][58] ^= mat[k][58] & mask;
					mat[row][59] ^= mat[k][59] & mask;
					mat[row][60] ^= mat[k][60] & mask;
					mat[row][61] ^= mat[k][61] & mask;
					mat[row][62] ^= mat[k][62] & mask;
					mat[row][63] ^= mat[k][63] & mask;
				}

				// return if not invertible
				if (((mat[row][i] >> j) & 1) == 0)
					return -1;

				for (k = 0; k < PKN_ROWS; k++)
				{
					if (k != row)
					{
						mask = mat[k][i] >> j;
						mask &= 1;
						mask = ~mask + 1;
						mat[k][0] ^= mat[row][0] & mask;
						mat[k][1] ^= mat[row][1] & mask;
						mat[k][2] ^= mat[row][2] & mask;
						mat[k][3] ^= mat[row][3] & mask;
						mat[k][4] ^= mat[row][4] & mask;
						mat[k][5] ^= mat[row][5] & mask;
						mat[k][6] ^= mat[row][6] & mask;
						mat[k][7] ^= mat[row][7] & mask;
						mat[k][8] ^= mat[row][8] & mask;
						mat[k][9] ^= mat[row][9] & mask;
						mat[k][10] ^= mat[row][10] & mask;
						mat[k][11] ^= mat[row][11] & mask;
						mat[k][12] ^= mat[row][12] & mask;
						mat[k][13] ^= mat[row][13] & mask;
						mat[k][14] ^= mat[row][14] & mask;
						mat[k][15] ^= mat[row][15] & mask;
						mat[k][16] ^= mat[row][16] & mask;
						mat[k][17] ^= mat[row][17] & mask;
						mat[k][18] ^= mat[row][18] & mask;
						mat[k][19] ^= mat[row][19] & mask;
						mat[k][20] ^= mat[row][20] & mask;
						mat[k][21] ^= mat[row][21] & mask;
						mat[k][22] ^= mat[row][22] & mask;
						mat[k][23] ^= mat[row][23] & mask;
						mat[k][24] ^= mat[row][24] & mask;
						mat[k][25] ^= mat[row][25] & mask;
						mat[k][26] ^= mat[row][26] & mask;
						mat[k][27] ^= mat[row][27] & mask;
						mat[k][28] ^= mat[row][28] & mask;
						mat[k][29] ^= mat[row][29] & mask;
						mat[k][30] ^= mat[row][30] & mask;
						mat[k][31] ^= mat[row][31] & mask;
						mat[k][32] ^= mat[row][32] & mask;
						mat[k][33] ^= mat[row][33] & mask;
						mat[k][34] ^= mat[row][34] & mask;
						mat[k][35] ^= mat[row][35] & mask;
						mat[k][36] ^= mat[row][36] & mask;
						mat[k][37] ^= mat[row][37] & mask;
						mat[k][38] ^= mat[row][38] & mask;
						mat[k][39] ^= mat[row][39] & mask;
						mat[k][40] ^= mat[row][40] & mask;
						mat[k][41] ^= mat[row][41] & mask;
						mat[k][42] ^= mat[row][42] & mask;
						mat[k][43] ^= mat[row][43] & mask;
						mat[k][44] ^= mat[row][44] & mask;
						mat[k][45] ^= mat[row][45] & mask;
						mat[k][46] ^= mat[row][46] & mask;
						mat[k][47] ^= mat[row][47] & mask;
						mat[k][48] ^= mat[row][48] & mask;
						mat[k][49] ^= mat[row][49] & mask;
						mat[k][50] ^= mat[row][50] & mask;
						mat[k][51] ^= mat[row][51] & mask;
						mat[k][52] ^= mat[row][52] & mask;
						mat[k][53] ^= mat[row][53] & mask;
						mat[k][54] ^= mat[row][54] & mask;
						mat[k][55] ^= mat[row][55] & mask;
						mat[k][56] ^= mat[row][56] & mask;
						mat[k][57] ^= mat[row][57] & mask;
						mat[k][58] ^= mat[row][58] & mask;
						mat[k][59] ^= mat[row][59] & mask;
						mat[k][60] ^= mat[row][60] & mask;
						mat[k][61] ^= mat[row][61] & mask;
						mat[k][62] ^= mat[row][62] & mask;
						mat[k][63] ^= mat[row][63] & mask;
					}
				}
			}
		}

		// store pk
		tail = (PKN_ROWS & 63) >> 3;
		size_t pos = 0;

		for (i = 0; i < PKN_ROWS; i++)
		{
			u = mat[i][(PKN_ROWS + 63) / 64 - 1];

			for (k = tail; k < 8; k++)
				PublicKey[pos + (k - tail)] = (u >> (8 * k)) & 0xFF;

			pos += 8 - tail;

			for (j = M; j < 64; j++)
			{
				IntUtils::Le64ToBytes(mat[i][j], PublicKey, pos);
				pos += 8;
			}
		}

		return 0;
	}

	//~~~FFT~~~//

	class AdditiveFFT
	{
	public:

		static void Transform(ulong Output[][M], ulong* Input)
		{
			RadixConversions(Input);
			Butterflies(Output, Input);
		}

	private:

		static void Butterflies(ulong Output[][M], ulong* Input)
		{
			size_t i;
			size_t j;
			size_t k;
			size_t s;
			size_t b;
			ulong tmp[M];
			ulong constsPos = 0;

			// broadcast
			for (j = 0; j < 64; j++)
			{
				Output[j][0] = (Input[0] >> ButterflyReverse[j]) & 1;
				Output[j][0] = ~Output[j][0] + 1;
				Output[j][1] = (Input[1] >> ButterflyReverse[j]) & 1;
				Output[j][1] = ~Output[j][1] + 1;
				Output[j][2] = (Input[2] >> ButterflyReverse[j]) & 1;
				Output[j][2] = ~Output[j][2] + 1;
				Output[j][3] = (Input[3] >> ButterflyReverse[j]) & 1;
				Output[j][3] = ~Output[j][3] + 1;
				Output[j][4] = (Input[4] >> ButterflyReverse[j]) & 1;
				Output[j][4] = ~Output[j][4] + 1;
				Output[j][5] = (Input[5] >> ButterflyReverse[j]) & 1;
				Output[j][5] = ~Output[j][5] + 1;
				Output[j][6] = (Input[6] >> ButterflyReverse[j]) & 1;
				Output[j][6] = ~Output[j][6] + 1;
				Output[j][7] = (Input[7] >> ButterflyReverse[j]) & 1;
				Output[j][7] = ~Output[j][7] + 1;
				Output[j][8] = (Input[8] >> ButterflyReverse[j]) & 1;
				Output[j][8] = ~Output[j][8] + 1;
				Output[j][9] = (Input[9] >> ButterflyReverse[j]) & 1;
				Output[j][9] = ~Output[j][9] + 1;
				Output[j][10] = (Input[10] >> ButterflyReverse[j]) & 1;
				Output[j][10] = ~Output[j][10] + 1;
				Output[j][11] = (Input[11] >> ButterflyReverse[j]) & 1;
				Output[j][11] = ~Output[j][11] + 1;
			}

			// butterflies
			for (i = 0; i <= 5; i++)
			{
				s = 1 << i;

				for (j = 0; j < 64; j += 2 * s)
				{
					for (k = j; k < j + s; k++)
					{
						GoppaMath::Multiply(tmp, Output[k + s], ButterflyConsts[constsPos + (k - j)]);
						Output[k][0] ^= tmp[0];
						Output[k + s][0] ^= Output[k][0];
						Output[k][1] ^= tmp[1];
						Output[k + s][1] ^= Output[k][1];
						Output[k][2] ^= tmp[2];
						Output[k + s][2] ^= Output[k][2];
						Output[k][3] ^= tmp[3];
						Output[k + s][3] ^= Output[k][3];
						Output[k][4] ^= tmp[4];
						Output[k + s][4] ^= Output[k][4];
						Output[k][5] ^= tmp[5];
						Output[k + s][5] ^= Output[k][5];
						Output[k][6] ^= tmp[6];
						Output[k + s][6] ^= Output[k][6];
						Output[k][7] ^= tmp[7];
						Output[k + s][7] ^= Output[k][7];
						Output[k][8] ^= tmp[8];
						Output[k + s][8] ^= Output[k][8];
						Output[k][9] ^= tmp[9];
						Output[k + s][9] ^= Output[k][9];
						Output[k][10] ^= tmp[10];
						Output[k + s][10] ^= Output[k][10];
						Output[k][11] ^= tmp[11];
						Output[k + s][11] ^= Output[k][11];
					}
				}

				constsPos += ((ulong)1 << i);
			}
		}

		static void RadixConversions(ulong* Input)
		{
			size_t j;

			// scaling
			for (j = 0; j < M; j++)
			{
				Input[j] ^= (Input[j] & RadixMask[4][0]) >> 16;
				Input[j] ^= (Input[j] & RadixMask[4][1]) >> 16;
				Input[j] ^= (Input[j] & RadixMask[3][0]) >> 8;
				Input[j] ^= (Input[j] & RadixMask[3][1]) >> 8;
				Input[j] ^= (Input[j] & RadixMask[2][0]) >> 4;
				Input[j] ^= (Input[j] & RadixMask[2][1]) >> 4;
				Input[j] ^= (Input[j] & RadixMask[1][0]) >> 2;
				Input[j] ^= (Input[j] & RadixMask[1][1]) >> 2;
				Input[j] ^= (Input[j] & RadixMask[0][0]) >> 1;
				Input[j] ^= (Input[j] & RadixMask[0][1]) >> 1;
			}
			GoppaMath::Multiply(Input, Input, RadixScalar[0]);

			for (j = 0; j < M; j++)
			{
				Input[j] ^= (Input[j] & RadixMask[4][0]) >> 16;
				Input[j] ^= (Input[j] & RadixMask[4][1]) >> 16;
				Input[j] ^= (Input[j] & RadixMask[3][0]) >> 8;
				Input[j] ^= (Input[j] & RadixMask[3][1]) >> 8;
				Input[j] ^= (Input[j] & RadixMask[2][0]) >> 4;
				Input[j] ^= (Input[j] & RadixMask[2][1]) >> 4;
				Input[j] ^= (Input[j] & RadixMask[1][0]) >> 2;
				Input[j] ^= (Input[j] & RadixMask[1][1]) >> 2;
			}
			GoppaMath::Multiply(Input, Input, RadixScalar[1]);

			for (j = 0; j < M; j++)
			{
				Input[j] ^= (Input[j] & RadixMask[4][0]) >> 16;
				Input[j] ^= (Input[j] & RadixMask[4][1]) >> 16;
				Input[j] ^= (Input[j] & RadixMask[3][0]) >> 8;
				Input[j] ^= (Input[j] & RadixMask[3][1]) >> 8;
				Input[j] ^= (Input[j] & RadixMask[2][0]) >> 4;
				Input[j] ^= (Input[j] & RadixMask[2][1]) >> 4;

			}
			GoppaMath::Multiply(Input, Input, RadixScalar[2]);

			for (j = 0; j < M; j++)
			{
				Input[j] ^= (Input[j] & RadixMask[4][0]) >> 16;
				Input[j] ^= (Input[j] & RadixMask[4][1]) >> 16;
				Input[j] ^= (Input[j] & RadixMask[3][0]) >> 8;
				Input[j] ^= (Input[j] & RadixMask[3][1]) >> 8;
			}
			GoppaMath::Multiply(Input, Input, RadixScalar[3]);

			for (j = 0; j < M; j++)
			{
				Input[j] ^= (Input[j] & RadixMask[4][0]) >> 16;
				Input[j] ^= (Input[j] & RadixMask[4][1]) >> 16;
			}
			GoppaMath::Multiply(Input, Input, RadixScalar[4]);
		}
	};

	class TransposedFFT
	{
	private:

		static const ulong RadixTrMask[6][2];
		static const ulong RadixTrScalar[5][2][12];

	public:

		static void Transform(ulong Output[][M], ulong Input[][M])
		{
			Butterflies(Output, Input);
			RadixConversions(Output);
		}

	private:

		static void Butterflies(ulong Output[][M], ulong Input[][M])
		{
			int i, j, k, s;
			ulong tmp[M];
			ulong pre[6][M];
			ulong buf[64];
			ulong constsPos = 63;
			const ushort beta[6] = { 8, 1300, 3408, 1354, 2341, 1154 };

			// butterflies

			for (i = 5; i >= 0; i--) // TODO: unroll?
			{
				s = 1 << i;
				constsPos -= s;

				for (j = 0; j < 64; j += 2 * s)
				{
					for (k = j; k < j + s; k++)
					{
						GoppaField::Add(Input[k], Input[k], Input[k + s], M);
						GoppaMath::Multiply(tmp, Input[k], ButterflyConsts[constsPos + (k - j)]);
						GoppaField::Add(Input[k + s], Input[k + s], tmp, M);
					}
				}
			}

			// transpose

			for (i = 0; i < M; i++) // TODO: unroll?
			{
				for (j = 0; j < 64; j++)
					buf[ButterflyReverse[j]] = Input[j][i];

				GoppaUtils::TransposeCompact64x64(buf, buf);

				for (j = 0; j < 64; j++)
					Input[j][i] = buf[j];
			}

			// broadcast
			GoppaField::Copy(pre[0], Input[32], M);
			GoppaField::Add(Input[33], Input[33], Input[32], M);
			GoppaField::Copy(pre[1], Input[33], M);
			GoppaField::Add(Input[35], Input[35], Input[33], M);
			GoppaField::Add(pre[0], pre[0], Input[35], M);
			GoppaField::Add(Input[34], Input[34], Input[35], M);
			GoppaField::Copy(pre[2], Input[34], M);
			GoppaField::Add(Input[38], Input[38], Input[34], M);
			GoppaField::Add(pre[0], pre[0], Input[38], M);
			GoppaField::Add(Input[39], Input[39], Input[38], M);
			GoppaField::Add(pre[1], pre[1], Input[39], M);
			GoppaField::Add(Input[37], Input[37], Input[39], M);
			GoppaField::Add(pre[0], pre[0], Input[37], M);
			GoppaField::Add(Input[36], Input[36], Input[37], M);
			GoppaField::Copy(pre[3], Input[36], M);
			GoppaField::Add(Input[44], Input[44], Input[36], M);
			GoppaField::Add(pre[0], pre[0], Input[44], M);
			GoppaField::Add(Input[45], Input[45], Input[44], M);
			GoppaField::Add(pre[1], pre[1], Input[45], M);
			GoppaField::Add(Input[47], Input[47], Input[45], M);
			GoppaField::Add(pre[0], pre[0], Input[47], M);
			GoppaField::Add(Input[46], Input[46], Input[47], M);
			GoppaField::Add(pre[2], pre[2], Input[46], M);
			GoppaField::Add(Input[42], Input[42], Input[46], M);
			GoppaField::Add(pre[0], pre[0], Input[42], M);
			GoppaField::Add(Input[43], Input[43], Input[42], M);
			GoppaField::Add(pre[1], pre[1], Input[43], M);
			GoppaField::Add(Input[41], Input[41], Input[43], M);
			GoppaField::Add(pre[0], pre[0], Input[41], M);
			GoppaField::Add(Input[40], Input[40], Input[41], M);
			GoppaField::Copy(pre[4], Input[40], M);
			GoppaField::Add(Input[56], Input[56], Input[40], M);
			GoppaField::Add(pre[0], pre[0], Input[56], M);
			GoppaField::Add(Input[57], Input[57], Input[56], M);
			GoppaField::Add(pre[1], pre[1], Input[57], M);
			GoppaField::Add(Input[59], Input[59], Input[57], M);
			GoppaField::Add(pre[0], pre[0], Input[59], M);
			GoppaField::Add(Input[58], Input[58], Input[59], M);
			GoppaField::Add(pre[2], pre[2], Input[58], M);
			GoppaField::Add(Input[62], Input[62], Input[58], M);
			GoppaField::Add(pre[0], pre[0], Input[62], M);
			GoppaField::Add(Input[63], Input[63], Input[62], M);
			GoppaField::Add(pre[1], pre[1], Input[63], M);
			GoppaField::Add(Input[61], Input[61], Input[63], M);
			GoppaField::Add(pre[0], pre[0], Input[61], M);
			GoppaField::Add(Input[60], Input[60], Input[61], M);
			GoppaField::Add(pre[3], pre[3], Input[60], M);
			GoppaField::Add(Input[52], Input[52], Input[60], M);
			GoppaField::Add(pre[0], pre[0], Input[52], M);
			GoppaField::Add(Input[53], Input[53], Input[52], M);
			GoppaField::Add(pre[1], pre[1], Input[53], M);
			GoppaField::Add(Input[55], Input[55], Input[53], M);
			GoppaField::Add(pre[0], pre[0], Input[55], M);
			GoppaField::Add(Input[54], Input[54], Input[55], M);
			GoppaField::Add(pre[2], pre[2], Input[54], M);
			GoppaField::Add(Input[50], Input[50], Input[54], M);
			GoppaField::Add(pre[0], pre[0], Input[50], M);
			GoppaField::Add(Input[51], Input[51], Input[50], M);
			GoppaField::Add(pre[1], pre[1], Input[51], M);
			GoppaField::Add(Input[49], Input[49], Input[51], M);
			GoppaField::Add(pre[0], pre[0], Input[49], M);
			GoppaField::Add(Input[48], Input[48], Input[49], M);
			GoppaField::Copy(pre[5], Input[48], M);
			GoppaField::Add(Input[16], Input[16], Input[48], M);
			GoppaField::Add(pre[0], pre[0], Input[16], M);
			GoppaField::Add(Input[17], Input[17], Input[16], M);
			GoppaField::Add(pre[1], pre[1], Input[17], M);
			GoppaField::Add(Input[19], Input[19], Input[17], M);
			GoppaField::Add(pre[0], pre[0], Input[19], M);
			GoppaField::Add(Input[18], Input[18], Input[19], M);
			GoppaField::Add(pre[2], pre[2], Input[18], M);
			GoppaField::Add(Input[22], Input[22], Input[18], M);
			GoppaField::Add(pre[0], pre[0], Input[22], M);
			GoppaField::Add(Input[23], Input[23], Input[22], M);
			GoppaField::Add(pre[1], pre[1], Input[23], M);
			GoppaField::Add(Input[21], Input[21], Input[23], M);
			GoppaField::Add(pre[0], pre[0], Input[21], M);
			GoppaField::Add(Input[20], Input[20], Input[21], M);
			GoppaField::Add(pre[3], pre[3], Input[20], M);
			GoppaField::Add(Input[28], Input[28], Input[20], M);
			GoppaField::Add(pre[0], pre[0], Input[28], M);
			GoppaField::Add(Input[29], Input[29], Input[28], M);
			GoppaField::Add(pre[1], pre[1], Input[29], M);
			GoppaField::Add(Input[31], Input[31], Input[29], M);
			GoppaField::Add(pre[0], pre[0], Input[31], M);
			GoppaField::Add(Input[30], Input[30], Input[31], M);
			GoppaField::Add(pre[2], pre[2], Input[30], M);
			GoppaField::Add(Input[26], Input[26], Input[30], M);
			GoppaField::Add(pre[0], pre[0], Input[26], M);
			GoppaField::Add(Input[27], Input[27], Input[26], M);
			GoppaField::Add(pre[1], pre[1], Input[27], M);
			GoppaField::Add(Input[25], Input[25], Input[27], M);
			GoppaField::Add(pre[0], pre[0], Input[25], M);
			GoppaField::Add(Input[24], Input[24], Input[25], M);
			GoppaField::Add(pre[4], pre[4], Input[24], M);
			GoppaField::Add(Input[8], Input[8], Input[24], M);
			GoppaField::Add(pre[0], pre[0], Input[8], M);
			GoppaField::Add(Input[9], Input[9], Input[8], M);
			GoppaField::Add(pre[1], pre[1], Input[9], M);
			GoppaField::Add(Input[11], Input[11], Input[9], M);
			GoppaField::Add(pre[0], pre[0], Input[11], M);
			GoppaField::Add(Input[10], Input[10], Input[11], M);
			GoppaField::Add(pre[2], pre[2], Input[10], M);
			GoppaField::Add(Input[14], Input[14], Input[10], M);
			GoppaField::Add(pre[0], pre[0], Input[14], M);
			GoppaField::Add(Input[15], Input[15], Input[14], M);
			GoppaField::Add(pre[1], pre[1], Input[15], M);
			GoppaField::Add(Input[13], Input[13], Input[15], M);
			GoppaField::Add(pre[0], pre[0], Input[13], M);
			GoppaField::Add(Input[12], Input[12], Input[13], M);
			GoppaField::Add(pre[3], pre[3], Input[12], M);
			GoppaField::Add(Input[4], Input[4], Input[12], M);
			GoppaField::Add(pre[0], pre[0], Input[4], M);
			GoppaField::Add(Input[5], Input[5], Input[4], M);
			GoppaField::Add(pre[1], pre[1], Input[5], M);
			GoppaField::Add(Input[7], Input[7], Input[5], M);
			GoppaField::Add(pre[0], pre[0], Input[7], M);
			GoppaField::Add(Input[6], Input[6], Input[7], M);
			GoppaField::Add(pre[2], pre[2], Input[6], M);
			GoppaField::Add(Input[2], Input[2], Input[6], M);
			GoppaField::Add(pre[0], pre[0], Input[2], M);
			GoppaField::Add(Input[3], Input[3], Input[2], M);
			GoppaField::Add(pre[1], pre[1], Input[3], M);
			GoppaField::Add(Input[1], Input[1], Input[3], M);
			GoppaField::Add(pre[0], pre[0], Input[1], M);
			GoppaField::Add(Output[0], Input[0], Input[1], M);

			for (j = 0; j < M; j++) // TODO: unroll?
			{
				tmp[j] = (beta[0] >> j) & 1;
				tmp[j] = ~tmp[j] + 1;
			}

			GoppaMath::Multiply(Output[1], pre[0], tmp);

			for (i = 1; i < 6; i++) // TODO: unroll?
			{
				for (j = 0; j < M; j++)
				{
					tmp[j] = (beta[i] >> j) & 1;
					tmp[j] = ~tmp[j] + 1;
				}

				GoppaMath::Multiply(tmp, pre[i], tmp);
				GoppaField::Add(Output[1], Output[1], tmp, M);
			}
		}

		static void RadixConversions(ulong Input[][M])
		{
			int i, j, k;



			for (j = 5; j >= 0; j--) // TODO: unroll?
			{
				if (j < 5)
				{
					GoppaMath::Multiply(Input[0], Input[0], RadixTrScalar[j][0]);
					GoppaMath::Multiply(Input[1], Input[1], RadixTrScalar[j][1]);
				}

				for (i = 0; i < M; i++)
				{
					for (k = j; k <= 4; k++)
					{
						Input[0][i] ^= (Input[0][i] & RadixTrMask[k][0]) << (1 << k);
						Input[0][i] ^= (Input[0][i] & RadixTrMask[k][1]) << (1 << k);

						Input[1][i] ^= (Input[1][i] & RadixTrMask[k][0]) << (1 << k);
						Input[1][i] ^= (Input[1][i] & RadixTrMask[k][1]) << (1 << k);
					}
				}

				for (i = 0; i < M; i++)
				{
					Input[1][i] ^= (Input[0][i] & RadixTrMask[5][0]) >> 32;
					Input[1][i] ^= (Input[1][i] & RadixTrMask[5][1]) << 32;
				}
			}
		}
	};

	//~~~Utils~~~//

	class GoppaMath
	{
	public:

		static void Invert(ulong* Output, const ulong* Input)
		{
			std::vector<ulong> tmpA(M);
			std::vector<ulong> tmpB(M);

			GoppaField::Copy(Output, Input, M);
			Square(Output, Output);
			Multiply(tmpA.data(), Output, Input);
			Square(Output, tmpA.data());
			Square(Output, Output);
			Multiply(tmpB.data(), Output, tmpA.data());
			Square(Output, tmpB.data());
			Square(Output, Output);
			Square(Output, Output);
			Square(Output, Output);
			Multiply(Output, Output, tmpB.data());
			Square(Output, Output);
			Square(Output, Output);
			Multiply(Output, Output, tmpA.data());
			Square(Output, Output);
			Multiply(Output, Output, Input);
			Square(Output, Output);
		}

		static void Multiply(ulong* Output, ulong* A, const ulong* B)
		{
			size_t i;
			std::vector<ulong> result(2 * M - 1);

			ulong t1 = A[11] & B[11];
			ulong t2 = A[11] & B[9];
			ulong t3 = A[11] & B[10];
			ulong t4 = A[9] & B[11];
			ulong t5 = A[10] & B[11];
			ulong t6 = A[10] & B[10];
			ulong t7 = A[10] & B[9];
			ulong t8 = A[9] & B[10];
			ulong t9 = A[9] & B[9];
			ulong t10 = t8 ^ t7;
			ulong t11 = t6 ^ t4;
			ulong t12 = t11 ^ t2;
			ulong t13 = t5 ^ t3;
			ulong t14 = A[8] & B[8];
			ulong t15 = A[8] & B[6];
			ulong t16 = A[8] & B[7];
			ulong t17 = A[6] & B[8];
			ulong t18 = A[7] & B[8];
			ulong t19 = A[7] & B[7];
			ulong t20 = A[7] & B[6];
			ulong t21 = A[6] & B[7];
			ulong t22 = A[6] & B[6];
			ulong t23 = t21 ^ t20;
			ulong t24 = t19 ^ t17;
			ulong t25 = t24 ^ t15;
			ulong t26 = t18 ^ t16;
			ulong t27 = A[5] & B[5];
			ulong t28 = A[5] & B[3];
			ulong t29 = A[5] & B[4];
			ulong t30 = A[3] & B[5];
			ulong t31 = A[4] & B[5];
			ulong t32 = A[4] & B[4];
			ulong t33 = A[4] & B[3];
			ulong t34 = A[3] & B[4];
			ulong t35 = A[3] & B[3];
			ulong t36 = t34 ^ t33;
			ulong t37 = t32 ^ t30;
			ulong t38 = t37 ^ t28;
			ulong t39 = t31 ^ t29;
			ulong t40 = A[2] & B[2];
			ulong t41 = A[2] & B[0];
			ulong t42 = A[2] & B[1];
			ulong t43 = A[0] & B[2];
			ulong t44 = A[1] & B[2];
			ulong t45 = A[1] & B[1];
			ulong t46 = A[1] & B[0];
			ulong t47 = A[0] & B[1];
			ulong t48 = A[0] & B[0];
			ulong t49 = t47 ^ t46;
			ulong t50 = t45 ^ t43;
			ulong t51 = t50 ^ t41;
			ulong t52 = t44 ^ t42;
			ulong t53 = t52 ^ t35;
			ulong t54 = t40 ^ t36;
			ulong t55 = t39 ^ t22;
			ulong t56 = t27 ^ t23;
			ulong t57 = t26 ^ t9;
			ulong t58 = t14 ^ t10;
			ulong t59 = B[6] ^ B[9];
			ulong t60 = B[7] ^ B[10];
			ulong t61 = B[8] ^ B[11];
			ulong t62 = A[6] ^ A[9];
			ulong t63 = A[7] ^ A[10];
			ulong t64 = A[8] ^ A[11];
			ulong t65 = t64 & t61;
			ulong t66 = t64 & t59;
			ulong t67 = t64 & t60;
			ulong t68 = t62 & t61;
			ulong t69 = t63 & t61;
			ulong t70 = t63 & t60;
			ulong t71 = t63 & t59;
			ulong t72 = t62 & t60;
			ulong t73 = t62 & t59;
			ulong t74 = t72 ^ t71;
			ulong t75 = t70 ^ t68;
			ulong t76 = t75 ^ t66;
			ulong t77 = t69 ^ t67;
			ulong t78 = B[0] ^ B[3];
			ulong t79 = B[1] ^ B[4];
			ulong t80 = B[2] ^ B[5];
			ulong t81 = A[0] ^ A[3];
			ulong t82 = A[1] ^ A[4];
			ulong t83 = A[2] ^ A[5];
			ulong t84 = t83 & t80;
			ulong t85 = t83 & t78;
			ulong t86 = t83 & t79;
			ulong t87 = t81 & t80;
			ulong t88 = t82 & t80;
			ulong t89 = t82 & t79;
			ulong t90 = t82 & t78;
			ulong t91 = t81 & t79;
			ulong t92 = t81 & t78;
			ulong t93 = t91 ^ t90;
			ulong t94 = t89 ^ t87;
			ulong t95 = t94 ^ t85;
			ulong t96 = t88 ^ t86;
			ulong t97 = t53 ^ t48;
			ulong t98 = t54 ^ t49;
			ulong t99 = t38 ^ t51;
			ulong t100 = t55 ^ t53;
			ulong t101 = t56 ^ t54;
			ulong t102 = t25 ^ t38;
			ulong t103 = t57 ^ t55;
			ulong t104 = t58 ^ t56;
			ulong t105 = t12 ^ t25;
			ulong t106 = t13 ^ t57;
			ulong t107 = t1 ^ t58;
			ulong t108 = t97 ^ t92;
			ulong t109 = t98 ^ t93;
			ulong t110 = t99 ^ t95;
			ulong t111 = t100 ^ t96;
			ulong t112 = t101 ^ t84;
			ulong t113 = t103 ^ t73;
			ulong t114 = t104 ^ t74;
			ulong t115 = t105 ^ t76;
			ulong t116 = t106 ^ t77;
			ulong t117 = t107 ^ t65;
			ulong t118 = B[3] ^ B[9];
			ulong t119 = B[4] ^ B[10];
			ulong t120 = B[5] ^ B[11];
			ulong t121 = B[0] ^ B[6];
			ulong t122 = B[1] ^ B[7];
			ulong t123 = B[2] ^ B[8];
			ulong t124 = A[3] ^ A[9];
			ulong t125 = A[4] ^ A[10];
			ulong t126 = A[5] ^ A[11];
			ulong t127 = A[0] ^ A[6];
			ulong t128 = A[1] ^ A[7];
			ulong t129 = A[2] ^ A[8];
			ulong t130 = t129 & t123;
			ulong t131 = t129 & t121;
			ulong t132 = t129 & t122;
			ulong t133 = t127 & t123;
			ulong t134 = t128 & t123;
			ulong t135 = t128 & t122;
			ulong t136 = t128 & t121;
			ulong t137 = t127 & t122;
			ulong t138 = t127 & t121;
			ulong t139 = t137 ^ t136;
			ulong t140 = t135 ^ t133;
			ulong t141 = t140 ^ t131;
			ulong t142 = t134 ^ t132;
			ulong t143 = t126 & t120;
			ulong t144 = t126 & t118;
			ulong t145 = t126 & t119;
			ulong t146 = t124 & t120;
			ulong t147 = t125 & t120;
			ulong t148 = t125 & t119;
			ulong t149 = t125 & t118;
			ulong t150 = t124 & t119;
			ulong t151 = t124 & t118;
			ulong t152 = t150 ^ t149;
			ulong t153 = t148 ^ t146;
			ulong t154 = t153 ^ t144;
			ulong t155 = t147 ^ t145;
			ulong t156 = t121 ^ t118;
			ulong t157 = t122 ^ t119;
			ulong t158 = t123 ^ t120;
			ulong t159 = t127 ^ t124;
			ulong t160 = t128 ^ t125;
			ulong t161 = t129 ^ t126;
			ulong t162 = t161 & t158;
			ulong t163 = t161 & t156;
			ulong t164 = t161 & t157;
			ulong t165 = t159 & t158;
			ulong t166 = t160 & t158;
			ulong t167 = t160 & t157;
			ulong t168 = t160 & t156;
			ulong t169 = t159 & t157;
			ulong t170 = t159 & t156;
			ulong t171 = t169 ^ t168;
			ulong t172 = t167 ^ t165;
			ulong t173 = t172 ^ t163;
			ulong t174 = t166 ^ t164;
			ulong t175 = t142 ^ t151;
			ulong t176 = t130 ^ t152;
			ulong t177 = t170 ^ t175;
			ulong t178 = t171 ^ t176;
			ulong t179 = t173 ^ t154;
			ulong t180 = t174 ^ t155;
			ulong t181 = t162 ^ t143;
			ulong t182 = t177 ^ t138;
			ulong t183 = t178 ^ t139;
			ulong t184 = t179 ^ t141;
			ulong t185 = t180 ^ t175;
			ulong t186 = t181 ^ t176;
			ulong t187 = t111 ^ t48;
			ulong t188 = t112 ^ t49;
			ulong t189 = t102 ^ t51;
			ulong t190 = t113 ^ t108;
			ulong t191 = t114 ^ t109;
			ulong t192 = t115 ^ t110;
			ulong t193 = t116 ^ t111;
			ulong t194 = t117 ^ t112;
			ulong t195 = t12 ^ t102;
			ulong t196 = t13 ^ t113;
			ulong t197 = t1 ^ t114;
			ulong t198 = t187 ^ t138;
			ulong t199 = t188 ^ t139;
			ulong t200 = t189 ^ t141;
			ulong t201 = t190 ^ t182;
			ulong t202 = t191 ^ t183;
			ulong t203 = t192 ^ t184;
			ulong t204 = t193 ^ t185;
			ulong t205 = t194 ^ t186;
			ulong t206 = t195 ^ t154;
			ulong t207 = t196 ^ t155;
			ulong t208 = t197 ^ t143;

			result[0] = t48;
			result[1] = t49;
			result[2] = t51;
			result[3] = t108;
			result[4] = t109;
			result[5] = t110;
			result[6] = t198;
			result[7] = t199;
			result[8] = t200;
			result[9] = t201;
			result[10] = t202;
			result[11] = t203;
			result[12] = t204;
			result[13] = t205;
			result[14] = t206;
			result[15] = t207;
			result[16] = t208;
			result[17] = t115;
			result[18] = t116;
			result[19] = t117;
			result[20] = t12;
			result[21] = t13;
			result[22] = t1;

			for (i = 2 * M - 2; i >= M; i--) // TODO: unroll?
			{
				result[i - 9] ^= result[i];
				result[i - M] ^= result[i];
			}

			std::memcpy(&Output[0], &result[0], M * sizeof(ulong));
			//for (i = 0; i < M; i++)
			//	Output[i] = result[i];
		}

		static void Multiply(ushort* Output, ushort* A, ushort* B)
		{
			size_t i;
			size_t j;

			std::vector<ushort> tmp(123, 0);

			for (i = 0; i < 62; i++)
			{
				for (j = 0; j < 62; j++)
					tmp[i + j] ^= GoppaField::Multiply(A[i], B[j], M);
			}

			for (i = 122; i >= 62; i--)
			{
				tmp[i - 55] ^= GoppaField::Multiply(tmp[i], (ushort)1763, M);
				tmp[i - 61] ^= GoppaField::Multiply(tmp[i], (ushort)1722, M);
				tmp[i - 62] ^= GoppaField::Multiply(tmp[i], (ushort)4033, M);
			}

			for (i = 0; i < 62; i++)
				Output[i] = tmp[i];
		}

		static void Square(ulong* Output, ulong* Input)
		{
			std::vector<ulong> result(M);

			result[0] = Input[0] ^ Input[6];
			result[1] = Input[11];
			result[2] = Input[1] ^ Input[7];
			result[3] = Input[6];
			result[4] = Input[2] ^ Input[11] ^ Input[8];
			result[5] = Input[7];
			result[6] = Input[3] ^ Input[9];
			result[7] = Input[8];
			result[8] = Input[4] ^ Input[10];
			result[9] = Input[9];
			result[10] = Input[5] ^ Input[11];
			result[11] = Input[10];

			for (size_t i = 0; i < M; i++) // TODO: unroll?
				Output[i] = result[i];
		}
	};
};

// old
#ifndef _CEX_FFTM12T622_H
#define _CEX_FFTM12T622_H

#include "CexDomain.h"
#include "GoppaField.h"
#include "GoppaUtils.h"
#include "IAeadMode.h"
#include "IDigest.h"
#include "IntUtils.h"
#include "IPrng.h"
#include "MemUtils.h"
#include "SymmetricKey.h"

NAMESPACE_MCELIECE

using Cipher::Symmetric::Block::Mode::IAeadMode;
using Digest::IDigest;
using Utility::IntUtils;
using Utility::MemUtils;
using Prng::IPrng;

/// <summary>
/// The McEliece M12T62 FFT
/// </summary>
class FFTM12T62
{
public:

	static const int M = 12;
	static const int T = 62;
	static const int PKN_ROWS = (T * M);
	static const int PKN_COLS = ((1 << M) - T * M);
	static const int IRR_SZE = (M * 8);
	static const int CND_SZE = (736 * 8);
	static const int SND_SZE = (PKN_ROWS / 8);
	static const int GEN_MAXR = 100;

	static int Decrypt(std::vector<byte> &E, const std::vector<byte> &PrivateKey, const std::vector<byte> &S)
	{
		size_t i;
		ulong t;
		ulong diff;
		std::vector<ulong> error(64);
		std::vector<ulong> locator(M);
		std::vector<ulong> recv(64);
		std::vector<ulong> cond(CND_SZE / 8);
		ulong inverse[64][M];
		ulong scaled[64][M];
		ulong eval[64][M];
		ulong sPriv[2][M];
		ulong sPrivCmp[2][M];

		IntUtils::BlockToLe<ulong>(PrivateKey, IRR_SZE, cond, 0, CND_SZE);
		PreProcess(recv, S);
		GoppaUtils::BenesCompact(recv.data(), cond.data(), 1);
		// scaling
		Scaling(scaled, inverse, PrivateKey, recv);
		// transposed FFT
		TransposedFFT::Transform(sPriv, scaled);
		SyndromeAdjust(sPriv);
		// Berlekamp Massey
		BerlekampMassey(locator, sPriv);
		// additive FFT
		AdditiveFFT::Transform(eval, locator.data());

		for (i = 0; i < 64; i++)
		{
			error[i] = GoppaField::Or(eval[i], M);
			error[i] = ~error[i];
		}

		// re-encrypt
		ScalingInverse(scaled, inverse, error);
		TransposedFFT::Transform(sPrivCmp, scaled);
		SyndromeAdjust(sPrivCmp);

		diff = 0;
		diff |= sPriv[0][0] ^ sPrivCmp[0][0];
		diff |= sPriv[0][1] ^ sPrivCmp[0][1];
		diff |= sPriv[0][2] ^ sPrivCmp[0][2];
		diff |= sPriv[0][3] ^ sPrivCmp[0][3];
		diff |= sPriv[0][4] ^ sPrivCmp[0][4];
		diff |= sPriv[0][5] ^ sPrivCmp[0][5];
		diff |= sPriv[0][6] ^ sPrivCmp[0][6];
		diff |= sPriv[0][7] ^ sPrivCmp[0][7];
		diff |= sPriv[0][8] ^ sPrivCmp[0][8];
		diff |= sPriv[0][9] ^ sPrivCmp[0][9];
		diff |= sPriv[0][10] ^ sPrivCmp[0][10];
		diff |= sPriv[0][11] ^ sPrivCmp[0][11];
		diff |= sPriv[1][0] ^ sPrivCmp[1][0];
		diff |= sPriv[1][1] ^ sPrivCmp[1][1];
		diff |= sPriv[1][2] ^ sPrivCmp[1][2];
		diff |= sPriv[1][3] ^ sPrivCmp[1][3];
		diff |= sPriv[1][4] ^ sPrivCmp[1][4];
		diff |= sPriv[1][5] ^ sPrivCmp[1][5];
		diff |= sPriv[1][6] ^ sPrivCmp[1][6];
		diff |= sPriv[1][7] ^ sPrivCmp[1][7];
		diff |= sPriv[1][8] ^ sPrivCmp[1][8];
		diff |= sPriv[1][9] ^ sPrivCmp[1][9];
		diff |= sPriv[1][10] ^ sPrivCmp[1][10];
		diff |= sPriv[1][11] ^ sPrivCmp[1][11];
		diff |= diff >> 32;
		diff |= diff >> 16;
		diff |= diff >> 8;
		t = diff & 0xFF;

		// compact and store
		GoppaUtils::BenesCompact(error.data(), cond.data(), 0);
		IntUtils::LeToBlock<ulong>(error, 0, E, 0, error.size() * sizeof(ulong));

		t |= GoppaUtils::Weight(error.data()) ^ T;
		t -= 1;
		t >>= 63;

		return (t - 1);
	}

	static void Encrypt(std::vector<byte> &S, std::vector<byte> &E, const std::vector<byte> &PublicKey, IPrng* Random)
	{
		GenE(E, Random);
		Syndrome(S, PublicKey, E);
	}

	static int Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, IPrng* Random)
	{
		size_t ctr;

		for (ctr = 0; ctr < GEN_MAXR; ++ctr)
		{
			SkGen(PrivateKey, Random);

			if (PkGen(PublicKey, PrivateKey) == 0)
				break;
		}

		return (ctr < GEN_MAXR) ? 0 : -1;
	}

private:

	//~~~Decrypt~~~//

	static void BerlekampMassey(std::vector<ulong> &Output, ulong Input[][M])
	{
		ushort N;
		ushort L;
		ushort mask16b;
		ushort d;
		ushort b;
		ushort bInv;
		ushort r;
		ulong maskNz;
		ulong maskLeq;
		ulong B[M];
		ulong prod[M];
		ulong tmpIn[M];
		ulong rVec[M];
		ulong tmpC[M];

		Output[0] = 1;
		std::memcpy(&B[0], &Output[0], M * sizeof(ulong));
		Output[0] <<= 63;
		B[0] <<= 62;
		b = 1;
		L = 0;

		for (N = 0; N < T * 2; N++)
		{
			// computing d
			if (N < 64)
			{
				//for (i = 0; i < M; i++) // TODO: unroll?
				//	tmpIn[i] = Input[0][i] << (63 - N);

				tmpIn[0] = Input[0][0] << (63 - N);
				tmpIn[1] = Input[0][1] << (63 - N);
				tmpIn[2] = Input[0][2] << (63 - N);
				tmpIn[3] = Input[0][3] << (63 - N);
				tmpIn[4] = Input[0][4] << (63 - N);
				tmpIn[5] = Input[0][5] << (63 - N);
				tmpIn[6] = Input[0][6] << (63 - N);
				tmpIn[7] = Input[0][7] << (63 - N);
				tmpIn[8] = Input[0][8] << (63 - N);
				tmpIn[9] = Input[0][9] << (63 - N);
				tmpIn[10] = Input[0][10] << (63 - N);
				tmpIn[11] = Input[0][11] << (63 - N);
			}
			else
			{
				//for (i = 0; i < M; i++) // TODO: unroll?
				//	tmpIn[i] = (Input[0][i] >> (N - 63)) | (Input[1][i] << (127 - N));

				tmpIn[0] = (Input[0][0] >> (N - 63)) | (Input[1][0] << (127 - N));
				tmpIn[1] = (Input[0][1] >> (N - 63)) | (Input[1][1] << (127 - N));
				tmpIn[2] = (Input[0][2] >> (N - 63)) | (Input[1][2] << (127 - N));
				tmpIn[3] = (Input[0][3] >> (N - 63)) | (Input[1][3] << (127 - N));
				tmpIn[4] = (Input[0][4] >> (N - 63)) | (Input[1][4] << (127 - N));
				tmpIn[5] = (Input[0][5] >> (N - 63)) | (Input[1][5] << (127 - N));
				tmpIn[6] = (Input[0][6] >> (N - 63)) | (Input[1][6] << (127 - N));
				tmpIn[7] = (Input[0][7] >> (N - 63)) | (Input[1][7] << (127 - N));
				tmpIn[8] = (Input[0][8] >> (N - 63)) | (Input[1][8] << (127 - N));
				tmpIn[9] = (Input[0][9] >> (N - 63)) | (Input[1][9] << (127 - N));
				tmpIn[10] = (Input[0][10] >> (N - 63)) | (Input[1][10] << (127 - N));
				tmpIn[11] = (Input[0][11] >> (N - 63)) | (Input[1][11] << (127 - N));
			}

			GoppaMath::Multiply(prod, Output.data(), tmpIn);
			d = GoppaUtils::Reduce(prod, M);

			// 3 cases
			bInv = GoppaField::Invert(b, M);
			r = GoppaField::Multiply(d, bInv, M);
			GoppaUtils::Insert(rVec, r, M);
			GoppaMath::Multiply(tmpC, rVec, B);

			tmpC[0] ^= Output[0];
			tmpC[1] ^= Output[1];
			tmpC[2] ^= Output[2];
			tmpC[3] ^= Output[3];
			tmpC[4] ^= Output[4];
			tmpC[5] ^= Output[5];
			tmpC[6] ^= Output[6];
			tmpC[7] ^= Output[7];
			tmpC[8] ^= Output[8];
			tmpC[9] ^= Output[9];
			tmpC[10] ^= Output[10];
			tmpC[11] ^= Output[11];

			maskNz = GoppaUtils::MaskNonZero64(d);
			maskLeq = GoppaUtils::MaskLeq64(L * 2, N);
			mask16b = (maskNz & maskLeq) & 0xFFFF;

			GoppaUtils::CMov(B, Output.data(), maskNz & maskLeq, M);
			GoppaField::Copy(Output.data(), tmpC, M);

			b = (d & mask16b) | (b & ~mask16b);
			L = ((N + 1 - L) & mask16b) | (L & ~mask16b);

			B[0] >>= 1;
			B[1] >>= 1;
			B[2] >>= 1;
			B[3] >>= 1;
			B[4] >>= 1;
			B[5] >>= 1;
			B[6] >>= 1;
			B[7] >>= 1;
			B[8] >>= 1;
			B[9] >>= 1;
			B[10] >>= 1;
			B[11] >>= 1;
		}

		Output[0] >>= 64 - (T + 1);
		Output[1] >>= 64 - (T + 1);
		Output[2] >>= 64 - (T + 1);
		Output[3] >>= 64 - (T + 1);
		Output[4] >>= 64 - (T + 1);
		Output[5] >>= 64 - (T + 1);
		Output[6] >>= 64 - (T + 1);
		Output[7] >>= 64 - (T + 1);
		Output[8] >>= 64 - (T + 1);
		Output[9] >>= 64 - (T + 1);
		Output[10] >>= 64 - (T + 1);
		Output[11] >>= 64 - (T + 1);
	}

	static void PreProcess(std::vector<ulong> &Received, const std::vector<byte> &S)
	{
		IntUtils::BlockToLe<ulong>(S, 0, Received, 0, SND_SZE - 5);
		Received[11] <<= 8;
		Received[11] |= S[92];
		Received[11] <<= 8;
		Received[11] |= S[91];
		Received[11] <<= 8;
		Received[11] |= S[90];
		Received[11] <<= 8;
		Received[11] |= S[89];
		Received[11] <<= 8;
		Received[11] |= S[88];
	}

	static void Scaling(ulong Output[][M], ulong Inverse[][M], const std::vector<byte> &PrivateKey, std::vector<ulong> &Received)
	{
		size_t i;
		std::vector<ulong> skInt(M);
		ulong eval[64][M];
		ulong tmp[M];

		// computing inverses
		IntUtils::BlockToLe<ulong>(PrivateKey, 0, skInt, 0, skInt.size() * sizeof(ulong));
		AdditiveFFT::Transform(eval, skInt.data());
		GoppaMath::Square(eval[0], eval[0]);
		GoppaField::Copy(Inverse[0], eval[0], M);

		for (i = 1; i < 64; i++)
		{
			GoppaMath::Square(eval[i], eval[i]);
			GoppaMath::Multiply(Inverse[i], Inverse[i - 1], eval[i]);
		}
		GoppaMath::Invert(tmp, Inverse[63]);

		i = 63;
		while (i--)
		{
			GoppaMath::Multiply(Inverse[i + 1], tmp, Inverse[i]);
			GoppaMath::Multiply(tmp, tmp, eval[i + 1]);
		}
		GoppaField::Copy(Inverse[0], tmp, M);

		for (i = 0; i < 64; i++)
		{
			Output[i][0] = Inverse[i][0] & Received[i];
			Output[i][1] = Inverse[i][1] & Received[i];
			Output[i][2] = Inverse[i][2] & Received[i];
			Output[i][3] = Inverse[i][3] & Received[i];
			Output[i][4] = Inverse[i][4] & Received[i];
			Output[i][5] = Inverse[i][5] & Received[i];
			Output[i][6] = Inverse[i][6] & Received[i];
			Output[i][7] = Inverse[i][7] & Received[i];
			Output[i][8] = Inverse[i][8] & Received[i];
			Output[i][9] = Inverse[i][9] & Received[i];
			Output[i][10] = Inverse[i][10] & Received[i];
			Output[i][11] = Inverse[i][11] & Received[i];
		}
	}

	static void ScalingInverse(ulong Output[][M], ulong Inverse[][M], std::vector<ulong> &Received)
	{
		for (size_t i = 0; i < 64; i++)
		{
			Output[i][0] = Inverse[i][0] & Received[i];
			Output[i][1] = Inverse[i][1] & Received[i];
			Output[i][2] = Inverse[i][2] & Received[i];
			Output[i][3] = Inverse[i][3] & Received[i];
			Output[i][4] = Inverse[i][4] & Received[i];
			Output[i][5] = Inverse[i][5] & Received[i];
			Output[i][6] = Inverse[i][6] & Received[i];
			Output[i][7] = Inverse[i][7] & Received[i];
			Output[i][8] = Inverse[i][8] & Received[i];
			Output[i][9] = Inverse[i][9] & Received[i];
			Output[i][10] = Inverse[i][10] & Received[i];
			Output[i][11] = Inverse[i][11] & Received[i];
		}
	}

	static void SyndromeAdjust(ulong Input[][M])
	{
		Input[1][0] <<= (128 - T * 2);
		Input[1][0] >>= (128 - T * 2);
		Input[1][1] <<= (128 - T * 2);
		Input[1][1] >>= (128 - T * 2);
		Input[1][2] <<= (128 - T * 2);
		Input[1][2] >>= (128 - T * 2);
		Input[1][3] <<= (128 - T * 2);
		Input[1][3] >>= (128 - T * 2);
		Input[1][4] <<= (128 - T * 2);
		Input[1][4] >>= (128 - T * 2);
		Input[1][5] <<= (128 - T * 2);
		Input[1][5] >>= (128 - T * 2);
		Input[1][6] <<= (128 - T * 2);
		Input[1][6] >>= (128 - T * 2);
		Input[1][7] <<= (128 - T * 2);
		Input[1][7] >>= (128 - T * 2);
		Input[1][8] <<= (128 - T * 2);
		Input[1][8] >>= (128 - T * 2);
		Input[1][9] <<= (128 - T * 2);
		Input[1][9] >>= (128 - T * 2);
		Input[1][10] <<= (128 - T * 2);
		Input[1][10] >>= (128 - T * 2);
		Input[1][11] <<= (128 - T * 2);
		Input[1][11] >>= (128 - T * 2);
	}

	//~~~Encrypt~~~//

	static void GenE(std::vector<byte> &E, Prng::IPrng* Random)
	{
		size_t i;
		size_t j;
		size_t eq;
		ulong mask;
		std::vector<ushort> ind(T);
		std::vector<ulong> eInt(64, 0);
		std::vector<ulong> val(T);

		while (1)
		{
			Random->Fill(ind, 0, ind.size());

			for (i = 0; i < T; i++)
				ind[i] &= (1 << M) - 1;

			eq = 0;
			for (i = 1; i < T; i++)
			{
				for (j = 0; j < i; j++)
				{
					if (ind[i] == ind[j])
						eq = 1;
				}
			}

			if (eq == 0)
				break;
		}

		for (j = 0; j < T; j++)
			val[j] = (ulong)1 << (ind[j] & 63);

		for (i = 0; i < 64; i++)
		{
			for (j = 0; j < T; j++)
			{
				mask = i ^ (ind[j] >> 6);
				mask -= 1;
				mask >>= 63;
				mask = ~mask + 1;
				eInt[i] |= val[j] & mask;
			}
		}

		IntUtils::LeToBlock<ulong>(eInt, 0, E, 0, eInt.size() * sizeof(ulong));
	}

	static void Syndrome(std::vector<byte> &S, const std::vector<byte> &PublicKey, const std::vector<byte> &E)
	{
		const size_t CSZE = ((PKN_COLS + 63) / 64);
		const size_t COLSZE = PKN_COLS / 8;
		size_t t;
		byte b;
		std::vector<ulong> eInt(CSZE, 0);
		std::vector<ulong> rowInt(CSZE, 0);
		std::vector<ulong> tmp(8, 0);

		MemUtils::Copy<byte>(E, 0, S, 0, SND_SZE);// consider standard memcpy, array too small (check the others)
		MemUtils::Copy<byte, ulong>(E, SND_SZE, eInt, 0, COLSZE);

		for (size_t i = 0; i < PKN_ROWS; i += 8)
		{
			for (t = 0; t < 8; t++)// TODO: unroll?
			{
				MemUtils::Copy<byte, ulong>(PublicKey, (i + t) * COLSZE, rowInt, 0, COLSZE);
				tmp[t] = 0;// why zero if assigning in next step?

				for (size_t j = 0; j < CSZE; j++)// unrolled?
					tmp[t] ^= eInt[j] & rowInt[j];// TODO: if tmp[t] = 0 ? why xor= ?
			}

			tmp[7] ^= (tmp[7] >> 32);
			tmp[7] ^= (tmp[7] >> 16);
			tmp[7] ^= (tmp[7] >> 8);
			tmp[7] ^= (tmp[7] >> 4);
			b = (0x6996 >> (tmp[7] & 0xF)) & 1;
			tmp[6] ^= (tmp[6] >> 32);
			tmp[6] ^= (tmp[6] >> 16);
			tmp[6] ^= (tmp[6] >> 8);
			tmp[6] ^= (tmp[6] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[6] & 0xF)) & 1;
			tmp[5] ^= (tmp[5] >> 32);
			tmp[5] ^= (tmp[5] >> 16);
			tmp[5] ^= (tmp[5] >> 8);
			tmp[5] ^= (tmp[5] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[5] & 0xF)) & 1;
			tmp[4] ^= (tmp[4] >> 32);
			tmp[4] ^= (tmp[4] >> 16);
			tmp[4] ^= (tmp[4] >> 8);
			tmp[4] ^= (tmp[4] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[4] & 0xF)) & 1;
			tmp[3] ^= (tmp[3] >> 32);
			tmp[3] ^= (tmp[3] >> 16);
			tmp[3] ^= (tmp[3] >> 8);
			tmp[3] ^= (tmp[3] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[3] & 0xF)) & 1;
			tmp[2] ^= (tmp[2] >> 32);
			tmp[2] ^= (tmp[2] >> 16);
			tmp[2] ^= (tmp[2] >> 8);
			tmp[2] ^= (tmp[2] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[2] & 0xF)) & 1;
			tmp[1] ^= (tmp[1] >> 32);
			tmp[1] ^= (tmp[1] >> 16);
			tmp[1] ^= (tmp[1] >> 8);
			tmp[1] ^= (tmp[1] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[1] & 0xF)) & 1;
			tmp[0] ^= (tmp[0] >> 32);
			tmp[0] ^= (tmp[0] >> 16);
			tmp[0] ^= (tmp[0] >> 8);
			tmp[0] ^= (tmp[0] >> 4);
			b <<= 1;
			b |= (0x6996 >> (tmp[0] & 0xF)) & 1;

			S[i / 8] ^= b;
		}
	}

	//~~~KeyGen~~~//

	static int IrrGen(std::vector<ushort> &Output, std::vector<ushort> &F)
	{
		size_t i;
		size_t j;
		size_t k;
		size_t c;
		ushort mask;
		ushort inverse;
		ushort t;
		ushort mat[T + 1][T];

		// fill matrix
		mat[0][0] = 1;
		for (i = 1; i < T; i++)
			mat[0][i] = 0;

		for (i = 0; i < T; i++)
			mat[1][i] = F[i];

		for (j = 2; j <= T; j++)
			GoppaMath::Multiply(mat[j], mat[j - 1], F.data());

		// gaussian
		for (j = 0; j < T; j++)
		{
			for (k = j + 1; k < T; k++)
			{
				mask = GoppaField::Diff(mat[j][j], mat[j][k]);

				for (c = 0; c < T + 1; c++)
					mat[c][j] ^= mat[c][k] & mask;
			}

			if (mat[j][j] == 0)
			{
				// return if not invertible
				return -1;
			}

			// compute inverse
			inverse = GoppaField::Invert(mat[j][j], M);

			for (c = 0; c < T + 1; c++)
				mat[c][j] = GoppaField::Multiply(mat[c][j], inverse, M);

			for (k = 0; k < T; k++)
			{
				t = mat[j][k];

				if (k != j)
				{
					for (c = 0; c < T + 1; c++)
						mat[c][k] ^= GoppaField::Multiply(mat[c][j], t, M);
				}
			}
		}

		for (i = 0; i < T; i++)
			Output[i] = mat[T][i];

		Output[T] = 1;

		return 0;
	}

	static void SkGen(std::vector<byte> &PrivateKey, Prng::IPrng* Random)
	{
		size_t i;
		size_t j;
		std::vector<ulong> cond(CND_SZE / 8);
		std::vector<ushort> f(T);
		std::vector<ulong> skInt(M, 0);
		std::vector<ushort> irr(T + 1);
		//ulong skInt[M];
		//ushort irr[T + 1];

		while (1)
		{
			Random->Fill(f, 0, f.size());

			for (i = 0; i < T; i++)
				f[i] &= (1 << M) - 1;

			if (IrrGen(irr, f) == 0)
				break;
		}

		for (i = 0; i < M; i++) // TODO: unroll?
		{
			//skInt[i] = 0;

			j = irr.size();

			//for (int j = T; j >= 0; j--)
			while (j--)
			{
				skInt[i] <<= 1;
				skInt[i] |= (irr[j] >> i) & 1;
			}

			IntUtils::Le64ToBytes(skInt[i], PrivateKey, i * 8);
			//GoppaUtils::Store64(PrivateKey, i * 8, skInt[i]);
		}

		Random->Fill(cond, 0, cond.size());

		for (i = 0; i < CND_SZE / 8; i++)
			IntUtils::Le64ToBytes(cond[i], PrivateKey, IRR_SZE + i * 8);
		//GoppaUtils::Store64(PrivateKey, IRR_SZE + i * 8, cond[i]);
	}

	static int PkGen(std::vector<byte> &PublicKey, const std::vector<byte> &PrivateKey)
	{
		int i, j, k;
		int row, c, tail;
		int pos = 0;
		ulong mask;
		ulong u;
		ulong mat[M * T][64];
		ulong skInt[M];
		ulong eval[64][M];
		ulong inverse[64][M];
		ulong tmp[M];
		ulong cond[CND_SZE / 8];

		ulong points[64][M] =
		{
			{
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0X0000000000000000,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			},
			{
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFFFFFFFFFF,
				0XFFFFFFFF00000000,
				0XFFFF0000FFFF0000,
				0XFF00FF00FF00FF00,
				0XF0F0F0F0F0F0F0F0,
				0XCCCCCCCCCCCCCCCC,
				0XAAAAAAAAAAAAAAAA,
			}

		};

		// compute the inverses
		for (i = 0; i < M; i++)
			skInt[i] = IntUtils::LeBytesTo64(PrivateKey, i * 8);
		//skInt[i] = GoppaUtils::Load64(PrivateKey, i * 8);

		AdditiveFFT::Transform(eval, skInt);
		GoppaField::Copy(inverse[0], eval[0], M);

		for (i = 1; i < 64; i++)
			GoppaMath::Multiply(inverse[i], inverse[i - 1], eval[i]);

		GoppaMath::Invert(tmp, inverse[63]);

		for (i = 62; i >= 0; i--)
		{
			GoppaMath::Multiply(inverse[i + 1], tmp, inverse[i]);
			GoppaMath::Multiply(tmp, tmp, eval[i + 1]);
		}

		GoppaField::Copy(inverse[0], tmp, M);

		// fill matrix 
		for (j = 0; j < 64; j++)
		{
			for (k = 0; k < M; k++) // TODO: unroll?
				mat[k][j] = inverse[j][k];
		}

		for (i = 1; i < T; i++)
		{
			for (j = 0; j < 64; j++)
			{
				GoppaMath::Multiply(inverse[j], inverse[j], points[j]);

				for (k = 0; k < M; k++) // TODO: unroll?
					mat[i * M + k][j] = inverse[j][k];
			}
		}

		// permute 
		for (i = 0; i < CND_SZE / 8; i++)
			cond[i] = IntUtils::LeBytesTo64(PrivateKey, IRR_SZE + i * 8);
		//cond[i] = GoppaUtils::Load64(PrivateKey, IRR_SZE + i * 8);

		for (i = 0; i < M * T; i++)
			GoppaUtils::BenesCompact(mat[i], cond, 0);

		// gaussian elimination 
		for (i = 0; i < (M * T + 63) / 64; i++) // TODO: optimize?
		{
			for (j = 0; j < 64; j++)
			{
				row = i * 64 + j;

				if (row >= M * T)
					break;

				for (k = row + 1; k < M * T; k++)
				{
					mask = mat[row][i] ^ mat[k][i];
					mask >>= j;
					mask &= 1;
					mask = ~mask + 1;

					for (c = 0; c < 64; c++)
						mat[row][c] ^= mat[k][c] & mask;
				}

				// return if not invertible
				if (((mat[row][i] >> j) & 1) == 0)
					return -1;

				for (k = 0; k < M * T; k++)
				{
					if (k != row)
					{
						mask = mat[k][i] >> j;
						mask &= 1;
						mask = ~mask + 1;

						for (c = 0; c < 64; c++)
							mat[k][c] ^= mat[row][c] & mask;
					}
				}
			}
		}

		// store pk
		tail = ((M * T) & 63) >> 3;

		for (i = 0; i < M * T; i++) // TODO: optimize?
		{
			u = mat[i][(M * T + 63) / 64 - 1];

			for (k = tail; k < 8; k++)
				PublicKey[pos + (k - tail)] = (u >> (8 * k)) & 0xFF;

			pos += 8 - tail;

			for (j = (M * T + 63) / 64; j < 64; j++)
			{
				IntUtils::Le64ToBytes(mat[i][j], PublicKey, pos);
				//GoppaUtils::Store64(PublicKey.data(), pos, mat[i][j]);
				pos += 8;
			}
		}

		return 0;
	}

	//~~~FFT~~~//

	class AdditiveFFT
	{
	public:

		static void Transform(ulong Output[][M], ulong *Input)
		{
			RadixConversions(Input);
			Butterflies(Output, Input);
		}

	private:

		static void Butterflies(ulong Output[][M], ulong *Input)
		{
			size_t i;
			size_t j;
			size_t k;
			size_t s;
			size_t b;
			ulong tmp[M];
			ulong constsPos = 0;

			ulong consts[63][M] =
			{
				//64
				{
					0XF00F0FF0F00F0FF0,
					0XF0F00F0F0F0FF0F0,
					0X0FF00FF00FF00FF0,
					0XAA5555AAAA5555AA,
					0XF00F0FF0F00F0FF0,
					0X33CCCC33CC3333CC,
					0XFFFF0000FFFF0000,
					0XCC33CC3333CC33CC,
					0X33CC33CC33CC33CC,
					0X5A5A5A5A5A5A5A5A,
					0XFF00FF00FF00FF00,
					0XF00F0FF0F00F0FF0,
				},
				//128
				{
					0X3C3C3C3C3C3C3C3C,
					0XF0F0F0F0F0F0F0F0,
					0X5555AAAA5555AAAA,
					0XCC3333CCCC3333CC,
					0XC33CC33CC33CC33C,
					0X55555555AAAAAAAA,
					0X33333333CCCCCCCC,
					0X00FF00FFFF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0X0000000000000000,
					0X0000FFFFFFFF0000,
					0XF0F00F0F0F0FF0F0,
				},
				{
					0X3C3C3C3C3C3C3C3C,
					0X0F0F0F0F0F0F0F0F,
					0XAAAA5555AAAA5555,
					0XCC3333CCCC3333CC,
					0XC33CC33CC33CC33C,
					0X55555555AAAAAAAA,
					0X33333333CCCCCCCC,
					0XFF00FF0000FF00FF,
					0X0F0F0F0F0F0F0F0F,
					0X0000000000000000,
					0X0000FFFFFFFF0000,
					0XF0F00F0F0F0FF0F0,
				},
				//256
				{
					0XAA55AA5555AA55AA,
					0XCC33CC3333CC33CC,
					0X33CCCC33CC3333CC,
					0X55555555AAAAAAAA,
					0XFF0000FF00FFFF00,
					0X3CC33CC3C33CC33C,
					0X5555AAAA5555AAAA,
					0X0FF00FF00FF00FF0,
					0XCCCC33333333CCCC,
					0XF0F0F0F0F0F0F0F0,
					0X00FFFF0000FFFF00,
					0XC33CC33CC33CC33C,
				},
				{
					0X55AA55AAAA55AA55,
					0XCC33CC3333CC33CC,
					0XCC3333CC33CCCC33,
					0X55555555AAAAAAAA,
					0XFF0000FF00FFFF00,
					0XC33CC33C3CC33CC3,
					0XAAAA5555AAAA5555,
					0XF00FF00FF00FF00F,
					0X3333CCCCCCCC3333,
					0X0F0F0F0F0F0F0F0F,
					0XFF0000FFFF0000FF,
					0XC33CC33CC33CC33C,
				},
				{
					0XAA55AA5555AA55AA,
					0X33CC33CCCC33CC33,
					0XCC3333CC33CCCC33,
					0X55555555AAAAAAAA,
					0X00FFFF00FF0000FF,
					0X3CC33CC3C33CC33C,
					0X5555AAAA5555AAAA,
					0X0FF00FF00FF00FF0,
					0X3333CCCCCCCC3333,
					0XF0F0F0F0F0F0F0F0,
					0X00FFFF0000FFFF00,
					0XC33CC33CC33CC33C,
				},
				{
					0X55AA55AAAA55AA55,
					0X33CC33CCCC33CC33,
					0X33CCCC33CC3333CC,
					0X55555555AAAAAAAA,
					0X00FFFF00FF0000FF,
					0XC33CC33C3CC33CC3,
					0XAAAA5555AAAA5555,
					0XF00FF00FF00FF00F,
					0XCCCC33333333CCCC,
					0X0F0F0F0F0F0F0F0F,
					0XFF0000FFFF0000FF,
					0XC33CC33CC33CC33C,
				},
				//512
				{
					0X6699669999669966,
					0X33CCCC33CC3333CC,
					0XA5A5A5A55A5A5A5A,
					0X3C3CC3C3C3C33C3C,
					0XF00FF00F0FF00FF0,
					0X55AA55AA55AA55AA,
					0X3C3CC3C3C3C33C3C,
					0X0F0F0F0FF0F0F0F0,
					0X55AA55AA55AA55AA,
					0X33CCCC33CC3333CC,
					0XF0F0F0F0F0F0F0F0,
					0XA55A5AA55AA5A55A,
				},
				{
					0X9966996666996699,
					0X33CCCC33CC3333CC,
					0XA5A5A5A55A5A5A5A,
					0X3C3CC3C3C3C33C3C,
					0X0FF00FF0F00FF00F,
					0XAA55AA55AA55AA55,
					0X3C3CC3C3C3C33C3C,
					0XF0F0F0F00F0F0F0F,
					0XAA55AA55AA55AA55,
					0XCC3333CC33CCCC33,
					0X0F0F0F0F0F0F0F0F,
					0XA55A5AA55AA5A55A,
				},
				{
					0X6699669999669966,
					0X33CCCC33CC3333CC,
					0X5A5A5A5AA5A5A5A5,
					0XC3C33C3C3C3CC3C3,
					0X0FF00FF0F00FF00F,
					0XAA55AA55AA55AA55,
					0XC3C33C3C3C3CC3C3,
					0X0F0F0F0FF0F0F0F0,
					0XAA55AA55AA55AA55,
					0X33CCCC33CC3333CC,
					0XF0F0F0F0F0F0F0F0,
					0XA55A5AA55AA5A55A,
				},
				{
					0X9966996666996699,
					0X33CCCC33CC3333CC,
					0X5A5A5A5AA5A5A5A5,
					0XC3C33C3C3C3CC3C3,
					0XF00FF00F0FF00FF0,
					0X55AA55AA55AA55AA,
					0XC3C33C3C3C3CC3C3,
					0XF0F0F0F00F0F0F0F,
					0X55AA55AA55AA55AA,
					0XCC3333CC33CCCC33,
					0X0F0F0F0F0F0F0F0F,
					0XA55A5AA55AA5A55A,
				},
				{
					0X6699669999669966,
					0XCC3333CC33CCCC33,
					0X5A5A5A5AA5A5A5A5,
					0X3C3CC3C3C3C33C3C,
					0X0FF00FF0F00FF00F,
					0X55AA55AA55AA55AA,
					0X3C3CC3C3C3C33C3C,
					0X0F0F0F0FF0F0F0F0,
					0X55AA55AA55AA55AA,
					0X33CCCC33CC3333CC,
					0XF0F0F0F0F0F0F0F0,
					0XA55A5AA55AA5A55A,
				},
				{
					0X9966996666996699,
					0XCC3333CC33CCCC33,
					0X5A5A5A5AA5A5A5A5,
					0X3C3CC3C3C3C33C3C,
					0XF00FF00F0FF00FF0,
					0XAA55AA55AA55AA55,
					0X3C3CC3C3C3C33C3C,
					0XF0F0F0F00F0F0F0F,
					0XAA55AA55AA55AA55,
					0XCC3333CC33CCCC33,
					0X0F0F0F0F0F0F0F0F,
					0XA55A5AA55AA5A55A,
				},
				{
					0X6699669999669966,
					0XCC3333CC33CCCC33,
					0XA5A5A5A55A5A5A5A,
					0XC3C33C3C3C3CC3C3,
					0XF00FF00F0FF00FF0,
					0XAA55AA55AA55AA55,
					0XC3C33C3C3C3CC3C3,
					0X0F0F0F0FF0F0F0F0,
					0XAA55AA55AA55AA55,
					0X33CCCC33CC3333CC,
					0XF0F0F0F0F0F0F0F0,
					0XA55A5AA55AA5A55A,
				},
				{
					0X9966996666996699,
					0XCC3333CC33CCCC33,
					0XA5A5A5A55A5A5A5A,
					0XC3C33C3C3C3CC3C3,
					0X0FF00FF0F00FF00F,
					0X55AA55AA55AA55AA,
					0XC3C33C3C3C3CC3C3,
					0XF0F0F0F00F0F0F0F,
					0X55AA55AA55AA55AA,
					0XCC3333CC33CCCC33,
					0X0F0F0F0F0F0F0F0F,
					0XA55A5AA55AA5A55A,
				},
				//1024
				{
					0X9669699696696996,
					0X6996699669966996,
					0X6996699669966996,
					0X00FFFF0000FFFF00,
					0XFF00FF00FF00FF00,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X6996699669966996,
					0X00FFFF0000FFFF00,
					0X00FF00FF00FF00FF,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X6996699669966996,
					0XFF0000FFFF0000FF,
					0X00FF00FF00FF00FF,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X6996699669966996,
					0XFF0000FFFF0000FF,
					0XFF00FF00FF00FF00,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X9669966996699669,
					0XFF0000FFFF0000FF,
					0X00FF00FF00FF00FF,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X9669966996699669,
					0XFF0000FFFF0000FF,
					0XFF00FF00FF00FF00,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X9669966996699669,
					0X00FFFF0000FFFF00,
					0XFF00FF00FF00FF00,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X9669966996699669,
					0X00FFFF0000FFFF00,
					0X00FF00FF00FF00FF,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X9669966996699669,
					0X00FFFF0000FFFF00,
					0XFF00FF00FF00FF00,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X9669966996699669,
					0X00FFFF0000FFFF00,
					0X00FF00FF00FF00FF,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X9669966996699669,
					0XFF0000FFFF0000FF,
					0X00FF00FF00FF00FF,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X9669966996699669,
					0XFF0000FFFF0000FF,
					0XFF00FF00FF00FF00,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X6996699669966996,
					0XFF0000FFFF0000FF,
					0X00FF00FF00FF00FF,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X6996699669966996,
					0XFF0000FFFF0000FF,
					0XFF00FF00FF00FF00,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X6996699669966996,
					0X00FFFF0000FFFF00,
					0XFF00FF00FF00FF00,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X6996699669966996,
					0X00FFFF0000FFFF00,
					0X00FF00FF00FF00FF,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				//2048
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				}
			};

			const byte reversal[64] =
			{
				0, 32, 16, 48, 8, 40, 24, 56,
				4, 36, 20, 52, 12, 44, 28, 60,
				2, 34, 18, 50, 10, 42, 26, 58,
				6, 38, 22, 54, 14, 46, 30, 62,
				1, 33, 17, 49, 9, 41, 25, 57,
				5, 37, 21, 53, 13, 45, 29, 61,
				3, 35, 19, 51, 11, 43, 27, 59,
				7, 39, 23, 55, 15, 47, 31, 63 };

			// broadcast
			for (j = 0; j < 64; j++)
			{
				for (i = 0; i < M; i++) // TODO: unroll?
				{
					Output[j][i] = (Input[i] >> reversal[j]) & 1;
					Output[j][i] = ~Output[j][i] + 1;
				}
			}

			// butterflies
			for (i = 0; i <= 5; i++) // TODO: optimize?
			{
				s = 1 << i;

				for (j = 0; j < 64; j += 2 * s)
				{
					for (k = j; k < j + s; k++)
					{
						GoppaMath::Multiply(tmp, Output[k + s], consts[constsPos + (k - j)]);

						for (b = 0; b < M; b++)
							Output[k][b] ^= tmp[b];
						for (b = 0; b < M; b++)
							Output[k + s][b] ^= Output[k][b];
					}
				}

				constsPos += ((ulong)1 << i);
			}
		}

		static void RadixConversions(ulong *Input)
		{
			int i, j, k;

			const ulong mask[5][2] =
			{
				{ 0x8888888888888888, 0x4444444444444444 },
				{ 0xC0C0C0C0C0C0C0C0, 0x3030303030303030 },
				{ 0xF000F000F000F000, 0x0F000F000F000F00 },
				{ 0xFF000000FF000000, 0x00FF000000FF0000 },
				{ 0xFFFF000000000000, 0x0000FFFF00000000 }
			};

			const ulong s[5][M] =
			{
				{
					0XF3CFC030FC30F003,
					0X3FCF0F003C00C00C,
					0X30033CC300C0C03C,
					0XCCFF0F3C0F30F0C0,
					0X0300C03FF303C3F0,
					0X3FFF3C0FF0CCCCC0,
					0XF3FFF0C00F3C3CC0,
					0X3003333FFFC3C000,
					0X0FF30FFFC3FFF300,
					0XFFC0F300F0F0CC00,
					0XC0CFF3FCCC3CFC00,
					0XFC3C03F0F330C000,
				},
				{
					0X000F00000000F00F,
					0X00000F00F00000F0,
					0X0F00000F00000F00,
					0XF00F00F00F000000,
					0X00F00000000000F0,
					0X0000000F00000000,
					0XF00000000F00F000,
					0X00F00F00000F0000,
					0X0000F00000F00F00,
					0X000F00F00F00F000,
					0X00F00F0000000000,
					0X0000000000F00000,
				},
				{
					0X0000FF00FF0000FF,
					0X0000FF000000FF00,
					0XFF0000FF00FF0000,
					0XFFFF0000FF000000,
					0X00FF00FF00FF0000,
					0X0000FFFFFF000000,
					0X00FFFF00FF000000,
					0XFFFFFF0000FF0000,
					0XFFFF00FFFF00FF00,
					0X0000FF0000000000,
					0XFFFFFF00FF000000,
					0X00FF000000000000,
				},
				{
					0X000000000000FFFF,
					0X00000000FFFF0000,
					0X0000000000000000,
					0XFFFF000000000000,
					0X00000000FFFF0000,
					0X0000FFFF00000000,
					0X0000000000000000,
					0X00000000FFFF0000,
					0X0000FFFF00000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
				},
				{
					0X00000000FFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFFFFFF00000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
				}

			};

			for (i = 0; i <= 4; i++) // TODO: unroll?
			{
				for (j = 0; j < M; j++)
				{
					for (k = 4; k >= i; k--)
					{
						Input[j] ^= (Input[j] & mask[k][0]) >> (1 << k);
						Input[j] ^= (Input[j] & mask[k][1]) >> (1 << k);
					}
				}
				// Scaling
				GoppaMath::Multiply(Input, Input, s[i]);
			}
		}
	};

	class TransposedFFT
	{
	public:

		static void Transform(ulong Output[][M], ulong Input[][M])
		{
			Butterflies(Output, Input);
			RadixConversions(Output);
		}

	private:

		static void Butterflies(ulong Output[][M], ulong Input[][M])
		{
			int i, j, k, s;

			ulong tmp[M];
			ulong pre[6][M];
			ulong buf[64];

			const ulong consts[63][M] =
			{
				//64
				{
					0XF00F0FF0F00F0FF0,
					0XF0F00F0F0F0FF0F0,
					0X0FF00FF00FF00FF0,
					0XAA5555AAAA5555AA,
					0XF00F0FF0F00F0FF0,
					0X33CCCC33CC3333CC,
					0XFFFF0000FFFF0000,
					0XCC33CC3333CC33CC,
					0X33CC33CC33CC33CC,
					0X5A5A5A5A5A5A5A5A,
					0XFF00FF00FF00FF00,
					0XF00F0FF0F00F0FF0,
				},
				//128
				{
					0X3C3C3C3C3C3C3C3C,
					0XF0F0F0F0F0F0F0F0,
					0X5555AAAA5555AAAA,
					0XCC3333CCCC3333CC,
					0XC33CC33CC33CC33C,
					0X55555555AAAAAAAA,
					0X33333333CCCCCCCC,
					0X00FF00FFFF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0X0000000000000000,
					0X0000FFFFFFFF0000,
					0XF0F00F0F0F0FF0F0,
				},
				{
					0X3C3C3C3C3C3C3C3C,
					0X0F0F0F0F0F0F0F0F,
					0XAAAA5555AAAA5555,
					0XCC3333CCCC3333CC,
					0XC33CC33CC33CC33C,
					0X55555555AAAAAAAA,
					0X33333333CCCCCCCC,
					0XFF00FF0000FF00FF,
					0X0F0F0F0F0F0F0F0F,
					0X0000000000000000,
					0X0000FFFFFFFF0000,
					0XF0F00F0F0F0FF0F0,
				},
				//256
				{
					0XAA55AA5555AA55AA,
					0XCC33CC3333CC33CC,
					0X33CCCC33CC3333CC,
					0X55555555AAAAAAAA,
					0XFF0000FF00FFFF00,
					0X3CC33CC3C33CC33C,
					0X5555AAAA5555AAAA,
					0X0FF00FF00FF00FF0,
					0XCCCC33333333CCCC,
					0XF0F0F0F0F0F0F0F0,
					0X00FFFF0000FFFF00,
					0XC33CC33CC33CC33C,
				},
				{
					0X55AA55AAAA55AA55,
					0XCC33CC3333CC33CC,
					0XCC3333CC33CCCC33,
					0X55555555AAAAAAAA,
					0XFF0000FF00FFFF00,
					0XC33CC33C3CC33CC3,
					0XAAAA5555AAAA5555,
					0XF00FF00FF00FF00F,
					0X3333CCCCCCCC3333,
					0X0F0F0F0F0F0F0F0F,
					0XFF0000FFFF0000FF,
					0XC33CC33CC33CC33C,
				},
				{
					0XAA55AA5555AA55AA,
					0X33CC33CCCC33CC33,
					0XCC3333CC33CCCC33,
					0X55555555AAAAAAAA,
					0X00FFFF00FF0000FF,
					0X3CC33CC3C33CC33C,
					0X5555AAAA5555AAAA,
					0X0FF00FF00FF00FF0,
					0X3333CCCCCCCC3333,
					0XF0F0F0F0F0F0F0F0,
					0X00FFFF0000FFFF00,
					0XC33CC33CC33CC33C,
				},
				{
					0X55AA55AAAA55AA55,
					0X33CC33CCCC33CC33,
					0X33CCCC33CC3333CC,
					0X55555555AAAAAAAA,
					0X00FFFF00FF0000FF,
					0XC33CC33C3CC33CC3,
					0XAAAA5555AAAA5555,
					0XF00FF00FF00FF00F,
					0XCCCC33333333CCCC,
					0X0F0F0F0F0F0F0F0F,
					0XFF0000FFFF0000FF,
					0XC33CC33CC33CC33C,
				},
				//512
				{
					0X6699669999669966,
					0X33CCCC33CC3333CC,
					0XA5A5A5A55A5A5A5A,
					0X3C3CC3C3C3C33C3C,
					0XF00FF00F0FF00FF0,
					0X55AA55AA55AA55AA,
					0X3C3CC3C3C3C33C3C,
					0X0F0F0F0FF0F0F0F0,
					0X55AA55AA55AA55AA,
					0X33CCCC33CC3333CC,
					0XF0F0F0F0F0F0F0F0,
					0XA55A5AA55AA5A55A,
				},
				{
					0X9966996666996699,
					0X33CCCC33CC3333CC,
					0XA5A5A5A55A5A5A5A,
					0X3C3CC3C3C3C33C3C,
					0X0FF00FF0F00FF00F,
					0XAA55AA55AA55AA55,
					0X3C3CC3C3C3C33C3C,
					0XF0F0F0F00F0F0F0F,
					0XAA55AA55AA55AA55,
					0XCC3333CC33CCCC33,
					0X0F0F0F0F0F0F0F0F,
					0XA55A5AA55AA5A55A,
				},
				{
					0X6699669999669966,
					0X33CCCC33CC3333CC,
					0X5A5A5A5AA5A5A5A5,
					0XC3C33C3C3C3CC3C3,
					0X0FF00FF0F00FF00F,
					0XAA55AA55AA55AA55,
					0XC3C33C3C3C3CC3C3,
					0X0F0F0F0FF0F0F0F0,
					0XAA55AA55AA55AA55,
					0X33CCCC33CC3333CC,
					0XF0F0F0F0F0F0F0F0,
					0XA55A5AA55AA5A55A,
				},
				{
					0X9966996666996699,
					0X33CCCC33CC3333CC,
					0X5A5A5A5AA5A5A5A5,
					0XC3C33C3C3C3CC3C3,
					0XF00FF00F0FF00FF0,
					0X55AA55AA55AA55AA,
					0XC3C33C3C3C3CC3C3,
					0XF0F0F0F00F0F0F0F,
					0X55AA55AA55AA55AA,
					0XCC3333CC33CCCC33,
					0X0F0F0F0F0F0F0F0F,
					0XA55A5AA55AA5A55A,
				},
				{
					0X6699669999669966,
					0XCC3333CC33CCCC33,
					0X5A5A5A5AA5A5A5A5,
					0X3C3CC3C3C3C33C3C,
					0X0FF00FF0F00FF00F,
					0X55AA55AA55AA55AA,
					0X3C3CC3C3C3C33C3C,
					0X0F0F0F0FF0F0F0F0,
					0X55AA55AA55AA55AA,
					0X33CCCC33CC3333CC,
					0XF0F0F0F0F0F0F0F0,
					0XA55A5AA55AA5A55A,
				},
				{
					0X9966996666996699,
					0XCC3333CC33CCCC33,
					0X5A5A5A5AA5A5A5A5,
					0X3C3CC3C3C3C33C3C,
					0XF00FF00F0FF00FF0,
					0XAA55AA55AA55AA55,
					0X3C3CC3C3C3C33C3C,
					0XF0F0F0F00F0F0F0F,
					0XAA55AA55AA55AA55,
					0XCC3333CC33CCCC33,
					0X0F0F0F0F0F0F0F0F,
					0XA55A5AA55AA5A55A,
				},
				{
					0X6699669999669966,
					0XCC3333CC33CCCC33,
					0XA5A5A5A55A5A5A5A,
					0XC3C33C3C3C3CC3C3,
					0XF00FF00F0FF00FF0,
					0XAA55AA55AA55AA55,
					0XC3C33C3C3C3CC3C3,
					0X0F0F0F0FF0F0F0F0,
					0XAA55AA55AA55AA55,
					0X33CCCC33CC3333CC,
					0XF0F0F0F0F0F0F0F0,
					0XA55A5AA55AA5A55A,
				},
				{
					0X9966996666996699,
					0XCC3333CC33CCCC33,
					0XA5A5A5A55A5A5A5A,
					0XC3C33C3C3C3CC3C3,
					0X0FF00FF0F00FF00F,
					0X55AA55AA55AA55AA,
					0XC3C33C3C3C3CC3C3,
					0XF0F0F0F00F0F0F0F,
					0X55AA55AA55AA55AA,
					0XCC3333CC33CCCC33,
					0X0F0F0F0F0F0F0F0F,
					0XA55A5AA55AA5A55A,
				},
				//1024
				{
					0X9669699696696996,
					0X6996699669966996,
					0X6996699669966996,
					0X00FFFF0000FFFF00,
					0XFF00FF00FF00FF00,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X6996699669966996,
					0X00FFFF0000FFFF00,
					0X00FF00FF00FF00FF,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X6996699669966996,
					0XFF0000FFFF0000FF,
					0X00FF00FF00FF00FF,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X6996699669966996,
					0XFF0000FFFF0000FF,
					0XFF00FF00FF00FF00,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X9669966996699669,
					0XFF0000FFFF0000FF,
					0X00FF00FF00FF00FF,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X9669966996699669,
					0XFF0000FFFF0000FF,
					0XFF00FF00FF00FF00,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X9669966996699669,
					0X00FFFF0000FFFF00,
					0XFF00FF00FF00FF00,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X6996699669966996,
					0X9669966996699669,
					0X00FFFF0000FFFF00,
					0X00FF00FF00FF00FF,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X9669966996699669,
					0X00FFFF0000FFFF00,
					0XFF00FF00FF00FF00,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X9669966996699669,
					0X00FFFF0000FFFF00,
					0X00FF00FF00FF00FF,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X9669966996699669,
					0XFF0000FFFF0000FF,
					0X00FF00FF00FF00FF,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X9669966996699669,
					0XFF0000FFFF0000FF,
					0XFF00FF00FF00FF00,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X6996699669966996,
					0XFF0000FFFF0000FF,
					0X00FF00FF00FF00FF,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X6996699669966996,
					0XFF0000FFFF0000FF,
					0XFF00FF00FF00FF00,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X6996699669966996,
					0X00FFFF0000FFFF00,
					0XFF00FF00FF00FF00,
					0X0FF00FF0F00FF00F,
					0X0F0FF0F0F0F00F0F,
					0XC33C3CC33CC3C33C,
					0XC33C3CC33CC3C33C,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				{
					0X9669699696696996,
					0X9669966996699669,
					0X6996699669966996,
					0X00FFFF0000FFFF00,
					0X00FF00FF00FF00FF,
					0XF00FF00F0FF00FF0,
					0XF0F00F0F0F0FF0F0,
					0X3CC3C33CC33C3CC3,
					0X3CC3C33CC33C3CC3,
					0XA55A5AA55AA5A55A,
					0XC33C3CC33CC3C33C,
					0X3CC3C33C3CC3C33C,
				},
				//2048
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0X0000000000000000,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				},
				{
					0X0000000000000000,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFFFFFFFFFF,
					0XFFFFFFFF00000000,
					0XFFFF0000FFFF0000,
					0XFF00FF00FF00FF00,
					0XF0F0F0F0F0F0F0F0,
					0XCCCCCCCCCCCCCCCC,
					0XAAAAAAAAAAAAAAAA,
				}
			};

			ulong constsPos = 63;

			const byte reversal[64] =
			{
				0, 32, 16, 48, 8, 40, 24, 56,
				4, 36, 20, 52, 12, 44, 28, 60,
				2, 34, 18, 50, 10, 42, 26, 58,
				6, 38, 22, 54, 14, 46, 30, 62,
				1, 33, 17, 49, 9, 41, 25, 57,
				5, 37, 21, 53, 13, 45, 29, 61,
				3, 35, 19, 51, 11, 43, 27, 59,
				7, 39, 23, 55, 15, 47, 31, 63
			};

			const ushort beta[6] = { 8, 1300, 3408, 1354, 2341, 1154 };

			// butterflies

			for (i = 5; i >= 0; i--) // TODO: unroll?
			{
				s = 1 << i;
				constsPos -= s;

				for (j = 0; j < 64; j += 2 * s)
				{
					for (k = j; k < j + s; k++)
					{
						GoppaField::Add(Input[k], Input[k], Input[k + s], M);
						GoppaMath::Multiply(tmp, Input[k], consts[constsPos + (k - j)]);
						GoppaField::Add(Input[k + s], Input[k + s], tmp, M);
					}
				}
			}

			// transpose

			for (i = 0; i < M; i++) // TODO: unroll?
			{
				for (j = 0; j < 64; j++)
					buf[reversal[j]] = Input[j][i];

				GoppaUtils::TransposeCompact64x64(buf, buf);

				for (j = 0; j < 64; j++)
					Input[j][i] = buf[j];
			}

			// broadcast

			GoppaField::Copy(pre[0], Input[32], M);
			GoppaField::Add(Input[33], Input[33], Input[32], M);
			GoppaField::Copy(pre[1], Input[33], M);
			GoppaField::Add(Input[35], Input[35], Input[33], M);
			GoppaField::Add(pre[0], pre[0], Input[35], M);
			GoppaField::Add(Input[34], Input[34], Input[35], M);
			GoppaField::Copy(pre[2], Input[34], M);
			GoppaField::Add(Input[38], Input[38], Input[34], M);
			GoppaField::Add(pre[0], pre[0], Input[38], M);
			GoppaField::Add(Input[39], Input[39], Input[38], M);
			GoppaField::Add(pre[1], pre[1], Input[39], M);
			GoppaField::Add(Input[37], Input[37], Input[39], M);
			GoppaField::Add(pre[0], pre[0], Input[37], M);
			GoppaField::Add(Input[36], Input[36], Input[37], M);
			GoppaField::Copy(pre[3], Input[36], M);
			GoppaField::Add(Input[44], Input[44], Input[36], M);
			GoppaField::Add(pre[0], pre[0], Input[44], M);
			GoppaField::Add(Input[45], Input[45], Input[44], M);
			GoppaField::Add(pre[1], pre[1], Input[45], M);
			GoppaField::Add(Input[47], Input[47], Input[45], M);
			GoppaField::Add(pre[0], pre[0], Input[47], M);
			GoppaField::Add(Input[46], Input[46], Input[47], M);
			GoppaField::Add(pre[2], pre[2], Input[46], M);
			GoppaField::Add(Input[42], Input[42], Input[46], M);
			GoppaField::Add(pre[0], pre[0], Input[42], M);
			GoppaField::Add(Input[43], Input[43], Input[42], M);
			GoppaField::Add(pre[1], pre[1], Input[43], M);
			GoppaField::Add(Input[41], Input[41], Input[43], M);
			GoppaField::Add(pre[0], pre[0], Input[41], M);
			GoppaField::Add(Input[40], Input[40], Input[41], M);
			GoppaField::Copy(pre[4], Input[40], M);
			GoppaField::Add(Input[56], Input[56], Input[40], M);
			GoppaField::Add(pre[0], pre[0], Input[56], M);
			GoppaField::Add(Input[57], Input[57], Input[56], M);
			GoppaField::Add(pre[1], pre[1], Input[57], M);
			GoppaField::Add(Input[59], Input[59], Input[57], M);
			GoppaField::Add(pre[0], pre[0], Input[59], M);
			GoppaField::Add(Input[58], Input[58], Input[59], M);
			GoppaField::Add(pre[2], pre[2], Input[58], M);
			GoppaField::Add(Input[62], Input[62], Input[58], M);
			GoppaField::Add(pre[0], pre[0], Input[62], M);
			GoppaField::Add(Input[63], Input[63], Input[62], M);
			GoppaField::Add(pre[1], pre[1], Input[63], M);
			GoppaField::Add(Input[61], Input[61], Input[63], M);
			GoppaField::Add(pre[0], pre[0], Input[61], M);
			GoppaField::Add(Input[60], Input[60], Input[61], M);
			GoppaField::Add(pre[3], pre[3], Input[60], M);
			GoppaField::Add(Input[52], Input[52], Input[60], M);
			GoppaField::Add(pre[0], pre[0], Input[52], M);
			GoppaField::Add(Input[53], Input[53], Input[52], M);
			GoppaField::Add(pre[1], pre[1], Input[53], M);
			GoppaField::Add(Input[55], Input[55], Input[53], M);
			GoppaField::Add(pre[0], pre[0], Input[55], M);
			GoppaField::Add(Input[54], Input[54], Input[55], M);
			GoppaField::Add(pre[2], pre[2], Input[54], M);
			GoppaField::Add(Input[50], Input[50], Input[54], M);
			GoppaField::Add(pre[0], pre[0], Input[50], M);
			GoppaField::Add(Input[51], Input[51], Input[50], M);
			GoppaField::Add(pre[1], pre[1], Input[51], M);
			GoppaField::Add(Input[49], Input[49], Input[51], M);
			GoppaField::Add(pre[0], pre[0], Input[49], M);
			GoppaField::Add(Input[48], Input[48], Input[49], M);
			GoppaField::Copy(pre[5], Input[48], M);
			GoppaField::Add(Input[16], Input[16], Input[48], M);
			GoppaField::Add(pre[0], pre[0], Input[16], M);
			GoppaField::Add(Input[17], Input[17], Input[16], M);
			GoppaField::Add(pre[1], pre[1], Input[17], M);
			GoppaField::Add(Input[19], Input[19], Input[17], M);
			GoppaField::Add(pre[0], pre[0], Input[19], M);
			GoppaField::Add(Input[18], Input[18], Input[19], M);
			GoppaField::Add(pre[2], pre[2], Input[18], M);
			GoppaField::Add(Input[22], Input[22], Input[18], M);
			GoppaField::Add(pre[0], pre[0], Input[22], M);
			GoppaField::Add(Input[23], Input[23], Input[22], M);
			GoppaField::Add(pre[1], pre[1], Input[23], M);
			GoppaField::Add(Input[21], Input[21], Input[23], M);
			GoppaField::Add(pre[0], pre[0], Input[21], M);
			GoppaField::Add(Input[20], Input[20], Input[21], M);
			GoppaField::Add(pre[3], pre[3], Input[20], M);
			GoppaField::Add(Input[28], Input[28], Input[20], M);
			GoppaField::Add(pre[0], pre[0], Input[28], M);
			GoppaField::Add(Input[29], Input[29], Input[28], M);
			GoppaField::Add(pre[1], pre[1], Input[29], M);
			GoppaField::Add(Input[31], Input[31], Input[29], M);
			GoppaField::Add(pre[0], pre[0], Input[31], M);
			GoppaField::Add(Input[30], Input[30], Input[31], M);
			GoppaField::Add(pre[2], pre[2], Input[30], M);
			GoppaField::Add(Input[26], Input[26], Input[30], M);
			GoppaField::Add(pre[0], pre[0], Input[26], M);
			GoppaField::Add(Input[27], Input[27], Input[26], M);
			GoppaField::Add(pre[1], pre[1], Input[27], M);
			GoppaField::Add(Input[25], Input[25], Input[27], M);
			GoppaField::Add(pre[0], pre[0], Input[25], M);
			GoppaField::Add(Input[24], Input[24], Input[25], M);
			GoppaField::Add(pre[4], pre[4], Input[24], M);
			GoppaField::Add(Input[8], Input[8], Input[24], M);
			GoppaField::Add(pre[0], pre[0], Input[8], M);
			GoppaField::Add(Input[9], Input[9], Input[8], M);
			GoppaField::Add(pre[1], pre[1], Input[9], M);
			GoppaField::Add(Input[11], Input[11], Input[9], M);
			GoppaField::Add(pre[0], pre[0], Input[11], M);
			GoppaField::Add(Input[10], Input[10], Input[11], M);
			GoppaField::Add(pre[2], pre[2], Input[10], M);
			GoppaField::Add(Input[14], Input[14], Input[10], M);
			GoppaField::Add(pre[0], pre[0], Input[14], M);
			GoppaField::Add(Input[15], Input[15], Input[14], M);
			GoppaField::Add(pre[1], pre[1], Input[15], M);
			GoppaField::Add(Input[13], Input[13], Input[15], M);
			GoppaField::Add(pre[0], pre[0], Input[13], M);
			GoppaField::Add(Input[12], Input[12], Input[13], M);
			GoppaField::Add(pre[3], pre[3], Input[12], M);
			GoppaField::Add(Input[4], Input[4], Input[12], M);
			GoppaField::Add(pre[0], pre[0], Input[4], M);
			GoppaField::Add(Input[5], Input[5], Input[4], M);
			GoppaField::Add(pre[1], pre[1], Input[5], M);
			GoppaField::Add(Input[7], Input[7], Input[5], M);
			GoppaField::Add(pre[0], pre[0], Input[7], M);
			GoppaField::Add(Input[6], Input[6], Input[7], M);
			GoppaField::Add(pre[2], pre[2], Input[6], M);
			GoppaField::Add(Input[2], Input[2], Input[6], M);
			GoppaField::Add(pre[0], pre[0], Input[2], M);
			GoppaField::Add(Input[3], Input[3], Input[2], M);
			GoppaField::Add(pre[1], pre[1], Input[3], M);
			GoppaField::Add(Input[1], Input[1], Input[3], M);
			GoppaField::Add(pre[0], pre[0], Input[1], M);
			GoppaField::Add(Output[0], Input[0], Input[1], M);

			for (j = 0; j < M; j++) // TODO: unroll?
			{
				tmp[j] = (beta[0] >> j) & 1;
				tmp[j] = ~tmp[j] + 1;
			}

			GoppaMath::Multiply(Output[1], pre[0], tmp);

			for (i = 1; i < 6; i++) // TODO: unroll?
			{
				for (j = 0; j < M; j++)
				{
					tmp[j] = (beta[i] >> j) & 1;
					tmp[j] = ~tmp[j] + 1;
				}

				GoppaMath::Multiply(tmp, pre[i], tmp);
				GoppaField::Add(Output[1], Output[1], tmp, M);
			}
		}

		static void RadixConversions(ulong Input[][M])
		{
			int i, j, k;

			const ulong mask[6][2] =
			{
				{ 0x2222222222222222, 0x4444444444444444 },
				{ 0x0C0C0C0C0C0C0C0C, 0x3030303030303030 },
				{ 0x00F000F000F000F0, 0x0F000F000F000F00 },
				{ 0x0000FF000000FF00, 0x00FF000000FF0000 },
				{ 0x00000000FFFF0000, 0x0000FFFF00000000 },
				{ 0xFFFFFFFF00000000, 0x00000000FFFFFFFF }
			};

			const ulong s[5][2][M] = {
				{ {
						0XF3CFC030FC30F003,
						0X3FCF0F003C00C00C,
						0X30033CC300C0C03C,
						0XCCFF0F3C0F30F0C0,
						0X0300C03FF303C3F0,
						0X3FFF3C0FF0CCCCC0,
						0XF3FFF0C00F3C3CC0,
						0X3003333FFFC3C000,
						0X0FF30FFFC3FFF300,
						0XFFC0F300F0F0CC00,
						0XC0CFF3FCCC3CFC00,
						0XFC3C03F0F330C000,
					},
					{
						0X000C03C0C3C0330C,
						0XF330CFFCC00F33C0,
						0XCCF330F00F3C0333,
						0XFF03FFF3FF0CF0C0,
						0X3CC3FCF00FCC303C,
						0X0F000C0FC30303F3,
						0XCF0FC3FF333CCF3C,
						0X003F3FC3C0FF333F,
						0X3CC3F0F3CF0FF00F,
						0XF3F33CC03FC30CC0,
						0X3CC330CFC333F33F,
						0X3CC0303FF3C3FFFC,
					} },
					{ {
							0X000F00000000F00F,
							0X00000F00F00000F0,
							0X0F00000F00000F00,
							0XF00F00F00F000000,
							0X00F00000000000F0,
							0X0000000F00000000,
							0XF00000000F00F000,
							0X00F00F00000F0000,
							0X0000F00000F00F00,
							0X000F00F00F00F000,
							0X00F00F0000000000,
							0X0000000000F00000,
						},
						{
							0X0F00F00F00000000,
							0XF00000000000F000,
							0X00000F00000000F0,
							0X0F00F00000F00000,
							0X000F00000F00F00F,
							0X00F00F00F00F0000,
							0X0F00F00000000000,
							0X000000000F000000,
							0X00F00000000F00F0,
							0X0000F00F00000F00,
							0XF00000F00000F00F,
							0X00000F00F00F00F0,
						} },
						{ {
								0X0000FF00FF0000FF,
								0X0000FF000000FF00,
								0XFF0000FF00FF0000,
								0XFFFF0000FF000000,
								0X00FF00FF00FF0000,
								0X0000FFFFFF000000,
								0X00FFFF00FF000000,
								0XFFFFFF0000FF0000,
								0XFFFF00FFFF00FF00,
								0X0000FF0000000000,
								0XFFFFFF00FF000000,
								0X00FF000000000000,
							},
							{
								0XFF00FFFFFF000000,
								0XFF0000FFFF000000,
								0XFFFF00FFFF000000,
								0XFF00FFFFFFFFFF00,
								0X00000000FF00FF00,
								0XFFFFFFFF00FF0000,
								0X00FFFFFF00FF0000,
								0XFFFF00FFFF00FFFF,
								0XFFFF0000FFFFFFFF,
								0XFF00000000FF0000,
								0X000000FF00FF00FF,
								0X00FF00FF00FFFF00,
							} },
							{ {
									0X000000000000FFFF,
									0X00000000FFFF0000,
									0X0000000000000000,
									0XFFFF000000000000,
									0X00000000FFFF0000,
									0X0000FFFF00000000,
									0X0000000000000000,
									0X00000000FFFF0000,
									0X0000FFFF00000000,
									0X0000000000000000,
									0X0000000000000000,
									0X0000000000000000,
								},
								{
									0X0000000000000000,
									0XFFFF000000000000,
									0X0000000000000000,
									0X0000000000000000,
									0XFFFF00000000FFFF,
									0X0000000000000000,
									0X0000FFFF00000000,
									0XFFFF00000000FFFF,
									0X00000000FFFF0000,
									0X0000000000000000,
									0XFFFF00000000FFFF,
									0X00000000FFFF0000,
								} },
								{ {
										0X00000000FFFFFFFF,
										0XFFFFFFFF00000000,
										0XFFFFFFFF00000000,
										0X0000000000000000,
										0X0000000000000000,
										0XFFFFFFFF00000000,
										0X0000000000000000,
										0X0000000000000000,
										0XFFFFFFFF00000000,
										0X0000000000000000,
										0X0000000000000000,
										0X0000000000000000,
									},
									{
										0X0000000000000000,
										0X0000000000000000,
										0X00000000FFFFFFFF,
										0XFFFFFFFF00000000,
										0XFFFFFFFF00000000,
										0X0000000000000000,
										0XFFFFFFFF00000000,
										0XFFFFFFFFFFFFFFFF,
										0XFFFFFFFF00000000,
										0X0000000000000000,
										0XFFFFFFFFFFFFFFFF,
										0XFFFFFFFF00000000,
									} }

			};

			for (j = 5; j >= 0; j--) // TODO: unroll?
			{
				if (j < 5)
				{
					GoppaMath::Multiply(Input[0], Input[0], s[j][0]);
					GoppaMath::Multiply(Input[1], Input[1], s[j][1]);
				}

				for (i = 0; i < M; i++)
				{
					for (k = j; k <= 4; k++)
					{
						Input[0][i] ^= (Input[0][i] & mask[k][0]) << (1 << k);
						Input[0][i] ^= (Input[0][i] & mask[k][1]) << (1 << k);

						Input[1][i] ^= (Input[1][i] & mask[k][0]) << (1 << k);
						Input[1][i] ^= (Input[1][i] & mask[k][1]) << (1 << k);
					}
				}

				for (i = 0; i < M; i++)
				{
					Input[1][i] ^= (Input[0][i] & mask[5][0]) >> 32;
					Input[1][i] ^= (Input[1][i] & mask[5][1]) << 32;
				}
			}
		}
	};

	//~~~Utils~~~//

	class GoppaMath
	{
	public:

		static void Invert(ulong* Output, const ulong* Input)
		{
			std::vector<ulong> tmpA(M);
			std::vector<ulong> tmpB(M);

			GoppaField::Copy(Output, Input, M);
			Square(Output, Output);
			Multiply(tmpA.data(), Output, Input);
			Square(Output, tmpA.data());
			Square(Output, Output);
			Multiply(tmpB.data(), Output, tmpA.data());
			Square(Output, tmpB.data());
			Square(Output, Output);
			Square(Output, Output);
			Square(Output, Output);
			Multiply(Output, Output, tmpB.data());
			Square(Output, Output);
			Square(Output, Output);
			Multiply(Output, Output, tmpA.data());
			Square(Output, Output);
			Multiply(Output, Output, Input);
			Square(Output, Output);
		}

		static void Multiply(ulong* Output, ulong* A, const ulong* B)
		{
			size_t i;
			std::vector<ulong> result(2 * M - 1);

			ulong t1 = A[11] & B[11];
			ulong t2 = A[11] & B[9];
			ulong t3 = A[11] & B[10];
			ulong t4 = A[9] & B[11];
			ulong t5 = A[10] & B[11];
			ulong t6 = A[10] & B[10];
			ulong t7 = A[10] & B[9];
			ulong t8 = A[9] & B[10];
			ulong t9 = A[9] & B[9];
			ulong t10 = t8 ^ t7;
			ulong t11 = t6 ^ t4;
			ulong t12 = t11 ^ t2;
			ulong t13 = t5 ^ t3;
			ulong t14 = A[8] & B[8];
			ulong t15 = A[8] & B[6];
			ulong t16 = A[8] & B[7];
			ulong t17 = A[6] & B[8];
			ulong t18 = A[7] & B[8];
			ulong t19 = A[7] & B[7];
			ulong t20 = A[7] & B[6];
			ulong t21 = A[6] & B[7];
			ulong t22 = A[6] & B[6];
			ulong t23 = t21 ^ t20;
			ulong t24 = t19 ^ t17;
			ulong t25 = t24 ^ t15;
			ulong t26 = t18 ^ t16;
			ulong t27 = A[5] & B[5];
			ulong t28 = A[5] & B[3];
			ulong t29 = A[5] & B[4];
			ulong t30 = A[3] & B[5];
			ulong t31 = A[4] & B[5];
			ulong t32 = A[4] & B[4];
			ulong t33 = A[4] & B[3];
			ulong t34 = A[3] & B[4];
			ulong t35 = A[3] & B[3];
			ulong t36 = t34 ^ t33;
			ulong t37 = t32 ^ t30;
			ulong t38 = t37 ^ t28;
			ulong t39 = t31 ^ t29;
			ulong t40 = A[2] & B[2];
			ulong t41 = A[2] & B[0];
			ulong t42 = A[2] & B[1];
			ulong t43 = A[0] & B[2];
			ulong t44 = A[1] & B[2];
			ulong t45 = A[1] & B[1];
			ulong t46 = A[1] & B[0];
			ulong t47 = A[0] & B[1];
			ulong t48 = A[0] & B[0];
			ulong t49 = t47 ^ t46;
			ulong t50 = t45 ^ t43;
			ulong t51 = t50 ^ t41;
			ulong t52 = t44 ^ t42;
			ulong t53 = t52 ^ t35;
			ulong t54 = t40 ^ t36;
			ulong t55 = t39 ^ t22;
			ulong t56 = t27 ^ t23;
			ulong t57 = t26 ^ t9;
			ulong t58 = t14 ^ t10;
			ulong t59 = B[6] ^ B[9];
			ulong t60 = B[7] ^ B[10];
			ulong t61 = B[8] ^ B[11];
			ulong t62 = A[6] ^ A[9];
			ulong t63 = A[7] ^ A[10];
			ulong t64 = A[8] ^ A[11];
			ulong t65 = t64 & t61;
			ulong t66 = t64 & t59;
			ulong t67 = t64 & t60;
			ulong t68 = t62 & t61;
			ulong t69 = t63 & t61;
			ulong t70 = t63 & t60;
			ulong t71 = t63 & t59;
			ulong t72 = t62 & t60;
			ulong t73 = t62 & t59;
			ulong t74 = t72 ^ t71;
			ulong t75 = t70 ^ t68;
			ulong t76 = t75 ^ t66;
			ulong t77 = t69 ^ t67;
			ulong t78 = B[0] ^ B[3];
			ulong t79 = B[1] ^ B[4];
			ulong t80 = B[2] ^ B[5];
			ulong t81 = A[0] ^ A[3];
			ulong t82 = A[1] ^ A[4];
			ulong t83 = A[2] ^ A[5];
			ulong t84 = t83 & t80;
			ulong t85 = t83 & t78;
			ulong t86 = t83 & t79;
			ulong t87 = t81 & t80;
			ulong t88 = t82 & t80;
			ulong t89 = t82 & t79;
			ulong t90 = t82 & t78;
			ulong t91 = t81 & t79;
			ulong t92 = t81 & t78;
			ulong t93 = t91 ^ t90;
			ulong t94 = t89 ^ t87;
			ulong t95 = t94 ^ t85;
			ulong t96 = t88 ^ t86;
			ulong t97 = t53 ^ t48;
			ulong t98 = t54 ^ t49;
			ulong t99 = t38 ^ t51;
			ulong t100 = t55 ^ t53;
			ulong t101 = t56 ^ t54;
			ulong t102 = t25 ^ t38;
			ulong t103 = t57 ^ t55;
			ulong t104 = t58 ^ t56;
			ulong t105 = t12 ^ t25;
			ulong t106 = t13 ^ t57;
			ulong t107 = t1 ^ t58;
			ulong t108 = t97 ^ t92;
			ulong t109 = t98 ^ t93;
			ulong t110 = t99 ^ t95;
			ulong t111 = t100 ^ t96;
			ulong t112 = t101 ^ t84;
			ulong t113 = t103 ^ t73;
			ulong t114 = t104 ^ t74;
			ulong t115 = t105 ^ t76;
			ulong t116 = t106 ^ t77;
			ulong t117 = t107 ^ t65;
			ulong t118 = B[3] ^ B[9];
			ulong t119 = B[4] ^ B[10];
			ulong t120 = B[5] ^ B[11];
			ulong t121 = B[0] ^ B[6];
			ulong t122 = B[1] ^ B[7];
			ulong t123 = B[2] ^ B[8];
			ulong t124 = A[3] ^ A[9];
			ulong t125 = A[4] ^ A[10];
			ulong t126 = A[5] ^ A[11];
			ulong t127 = A[0] ^ A[6];
			ulong t128 = A[1] ^ A[7];
			ulong t129 = A[2] ^ A[8];
			ulong t130 = t129 & t123;
			ulong t131 = t129 & t121;
			ulong t132 = t129 & t122;
			ulong t133 = t127 & t123;
			ulong t134 = t128 & t123;
			ulong t135 = t128 & t122;
			ulong t136 = t128 & t121;
			ulong t137 = t127 & t122;
			ulong t138 = t127 & t121;
			ulong t139 = t137 ^ t136;
			ulong t140 = t135 ^ t133;
			ulong t141 = t140 ^ t131;
			ulong t142 = t134 ^ t132;
			ulong t143 = t126 & t120;
			ulong t144 = t126 & t118;
			ulong t145 = t126 & t119;
			ulong t146 = t124 & t120;
			ulong t147 = t125 & t120;
			ulong t148 = t125 & t119;
			ulong t149 = t125 & t118;
			ulong t150 = t124 & t119;
			ulong t151 = t124 & t118;
			ulong t152 = t150 ^ t149;
			ulong t153 = t148 ^ t146;
			ulong t154 = t153 ^ t144;
			ulong t155 = t147 ^ t145;
			ulong t156 = t121 ^ t118;
			ulong t157 = t122 ^ t119;
			ulong t158 = t123 ^ t120;
			ulong t159 = t127 ^ t124;
			ulong t160 = t128 ^ t125;
			ulong t161 = t129 ^ t126;
			ulong t162 = t161 & t158;
			ulong t163 = t161 & t156;
			ulong t164 = t161 & t157;
			ulong t165 = t159 & t158;
			ulong t166 = t160 & t158;
			ulong t167 = t160 & t157;
			ulong t168 = t160 & t156;
			ulong t169 = t159 & t157;
			ulong t170 = t159 & t156;
			ulong t171 = t169 ^ t168;
			ulong t172 = t167 ^ t165;
			ulong t173 = t172 ^ t163;
			ulong t174 = t166 ^ t164;
			ulong t175 = t142 ^ t151;
			ulong t176 = t130 ^ t152;
			ulong t177 = t170 ^ t175;
			ulong t178 = t171 ^ t176;
			ulong t179 = t173 ^ t154;
			ulong t180 = t174 ^ t155;
			ulong t181 = t162 ^ t143;
			ulong t182 = t177 ^ t138;
			ulong t183 = t178 ^ t139;
			ulong t184 = t179 ^ t141;
			ulong t185 = t180 ^ t175;
			ulong t186 = t181 ^ t176;
			ulong t187 = t111 ^ t48;
			ulong t188 = t112 ^ t49;
			ulong t189 = t102 ^ t51;
			ulong t190 = t113 ^ t108;
			ulong t191 = t114 ^ t109;
			ulong t192 = t115 ^ t110;
			ulong t193 = t116 ^ t111;
			ulong t194 = t117 ^ t112;
			ulong t195 = t12 ^ t102;
			ulong t196 = t13 ^ t113;
			ulong t197 = t1 ^ t114;
			ulong t198 = t187 ^ t138;
			ulong t199 = t188 ^ t139;
			ulong t200 = t189 ^ t141;
			ulong t201 = t190 ^ t182;
			ulong t202 = t191 ^ t183;
			ulong t203 = t192 ^ t184;
			ulong t204 = t193 ^ t185;
			ulong t205 = t194 ^ t186;
			ulong t206 = t195 ^ t154;
			ulong t207 = t196 ^ t155;
			ulong t208 = t197 ^ t143;

			result[0] = t48;
			result[1] = t49;
			result[2] = t51;
			result[3] = t108;
			result[4] = t109;
			result[5] = t110;
			result[6] = t198;
			result[7] = t199;
			result[8] = t200;
			result[9] = t201;
			result[10] = t202;
			result[11] = t203;
			result[12] = t204;
			result[13] = t205;
			result[14] = t206;
			result[15] = t207;
			result[16] = t208;
			result[17] = t115;
			result[18] = t116;
			result[19] = t117;
			result[20] = t12;
			result[21] = t13;
			result[22] = t1;

			for (i = 2 * M - 2; i >= M; i--) // TODO: unroll?
			{
				result[i - 9] ^= result[i];
				result[i - M] ^= result[i];
			}

			std::memcpy(&Output[0], &result[0], M * sizeof(ulong));
			//for (i = 0; i < M; i++)
			//	Output[i] = result[i];
		}

		static void Multiply(ushort* Output, ushort* A, ushort* B)
		{
			size_t i;
			size_t j;

			std::vector<ushort> tmp(123, 0);

			for (i = 0; i < 62; i++)
			{
				for (j = 0; j < 62; j++)
					tmp[i + j] ^= GoppaField::Multiply(A[i], B[j], M);
			}

			for (i = 122; i >= 62; i--)
			{
				tmp[i - 55] ^= GoppaField::Multiply(tmp[i], (ushort)1763, M);
				tmp[i - 61] ^= GoppaField::Multiply(tmp[i], (ushort)1722, M);
				tmp[i - 62] ^= GoppaField::Multiply(tmp[i], (ushort)4033, M);
			}

			for (i = 0; i < 62; i++)
				Output[i] = tmp[i];
		}

		static void Square(ulong* Output, ulong* Input)
		{
			std::vector<ulong> result(M);

			result[0] = Input[0] ^ Input[6];
			result[1] = Input[11];
			result[2] = Input[1] ^ Input[7];
			result[3] = Input[6];
			result[4] = Input[2] ^ Input[11] ^ Input[8];
			result[5] = Input[7];
			result[6] = Input[3] ^ Input[9];
			result[7] = Input[8];
			result[8] = Input[4] ^ Input[10];
			result[9] = Input[9];
			result[10] = Input[5] ^ Input[11];
			result[11] = Input[10];

			for (size_t i = 0; i < M; i++) // TODO: unroll?
				Output[i] = result[i];
		}
	};
};

NAMESPACE_MCELIECEEND
#endif

NAMESPACE_MCELIECEEND
#endif*/