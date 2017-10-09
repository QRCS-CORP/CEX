#ifndef _CEX_PFMQ40961N1024_H
#define _CEX_PFMQ40961N1024_H

#include "CexDomain.h"
#include "PolyMath.h"

NAMESPACE_RINGLWE

/**
* \internal
*/

// *** NOTE: This a non-functioning prototype and not to be used! *** //

/// <summary>
/// Q40961N1024 helper functions
/// </summary> 
class PFMQ40961N1024
{
public:

	template <class T>
	inline static T F(T &V0, T &V1, T &X, int Q)
	{
		const T NQ(Q);
		const T N1(1);
		T xit, t, r, b;

		b = X * T(2730); // TODO: ?
		t = b >> 25;
		b = X - t * NQ;
		b = T(12288) - b; // TODO: ?
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		b = T::ShiftRA(b, 31);
#else
		b >>= 31;
#endif
		t -= b;
		r = t & N1;
		xit = (t >> 1);
		V0 = xit + r;
		t -= N1;
		r = t & N1;
		V1 = (t >> 1) + r;
		T v = X - (V0 * T(2) * NQ);

		return Utility::PolyMath::Abs<T>(v);
	}

	template <class T>
	inline static T G(T &X, const int Q)
	{
		T t, c, b;

		b = X * T(2730); // TODO: ?
		t = b >> 27;
		b = X - t * T(49156); // TODO: ?
		b = T(49155) - b; // TODO: ?
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		b = T::ShiftRA(b, 31);
#else
		b >>= 31;
#endif
		t -= b;
		c = t & T(1);
		t >>= 1;
		t += c;
		t *= (T(8) * T(Q));
		t -= X;

		return Utility::PolyMath::Abs<T>(t);
	}

	template <class T>
	inline static void GetNoise(std::vector<ushort> &R, std::vector<byte> &Random, int Q)
	{
		T a, b, r;
		const T AIBMASK(0x01010101);
		const T BITMASK(0xff);

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		const T NQ(Q);
		const size_t VCTSZE = T::size() / sizeof(uint);
		std::vector<uint> tmpR(VCTSZE);
#else
		const size_t VCTSZE = 1;
#endif

		for (size_t i = 0; i < R.size(); i += VCTSZE)
		{
#if defined(__AVX512__)
			r.Load(Random[i + 15], Random[i + 14], Random[i + 13], Random[i + 12], Random[i + 11], Random[i + 10], Random[i + 9], Random[i] + 8), Random[i + 7], Random[i + 6], Random[i + 5], Random[i + 4], Random[i + 3], Random[i + 2], Random[i + 1], Random[i]);
#elif defined(__AVX2__)
			r.Load(Random[i + 7], Random[i + 6], Random[i + 5], Random[i + 4], Random[i + 3], Random[i + 2], Random[i + 1], Random[i]);
#elif defined(__AVX__)
			r.Load(Random[i + 3], Random[i + 2], Random[i + 1], Random[i]);
#else
			r = Random[i];
#endif
			T d(0);

			for (size_t j = 0; j < 8; j++)
				d += (r >> j) & AIBMASK;

			a = ((d >> 8) & BITMASK) + (d & BITMASK);
			b = (d >> 24) + ((d >> 16) & BITMASK);

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
			T vR(a + NQ - b);
			vR.Store(tmpR, 0);
			for (size_t j = 0; j < VCTSZE; ++j)
				R[j + i] = static_cast<ushort>(tmpR[j]);
#else
			R[i] = a + Q - b;
#endif
		}
	}

	template <class T>
	inline static void HelpRec(std::vector<ushort> &C, const std::vector<ushort> &V, std::vector<byte> &Random, int Q)
	{
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
		const T NQ(Q);
		const T N1(1);
		const T N2(2);
		const T N3(3);
		const T N4(4);
		const T N8(8);
		const size_t VCTSZE = T::size() / sizeof(uint);

		T k, r;
		T c0, c1, c2, c3;
		T t0, t1, t2, t3;
		std::vector<T> v0(4);
		std::vector<T> v1(4);
		std::vector<T> tmpV(4);
		std::vector<int> tmpC(VCTSZE * 4);

		for (size_t i = 0; i < V.size() / 4; i += VCTSZE)
		{
#	if defined(__AVX512__)
			r.Load((byte)((Random[i >> 3] >> (i & 7)) & 1), (byte)((Random[(i + 1) >> 3] >> ((i + 1) & 7)) & 1), (byte)((Random[(i + 2) >> 3] >> ((i + 2) & 7)) & 1), (byte)((Random[(i + 3) >> 3] >> ((i + 3) & 7)) & 1),
				(byte)((Random[(i + 4) >> 3] >> ((i + 4) & 7)) & 1), (byte)((Random[(i + 5) >> 3] >> ((i + 5) & 7)) & 1), (byte)((Random[(i + 6) >> 3] >> ((i + 6) & 7)) & 1), (byte)((Random[(i + 7) >> 3] >> ((i + 7) & 7)) & 1),
				(byte)((Random[(i + 8) >> 3] >> ((i + 8) & 7)) & 1), (byte)((Random[(i + 9) >> 3] >> ((i + 9) & 7)) & 1), (byte)((Random[(i + 10) >> 3] >> ((i + 10) & 7)) & 1), (byte)((Random[(i + 11) >> 3] >> ((i + 11) & 7)) & 1),
				(byte)((Random[(i + 12) >> 3] >> ((i + 12) & 7)) & 1), (byte)((Random[(i + 13) >> 3] >> ((i + 13) & 7)) & 1), (byte)((Random[(i + 14) >> 3] >> ((i + 14) & 7)) & 1), (byte)((Random[(i + 15) >> 3] >> ((i + 15) & 7)) & 1));
#	elif defined(__AVX2__)
			r.Load((byte)((Random[i >> 3] >> (i & 7)) & 1), (byte)((Random[(i + 1) >> 3] >> ((i + 1) & 7)) & 1), (byte)((Random[(i + 2) >> 3] >> ((i + 2) & 7)) & 1), (byte)((Random[(i + 3) >> 3] >> ((i + 3) & 7)) & 1),
				(byte)((Random[(i + 4) >> 3] >> ((i + 4) & 7)) & 1), (byte)((Random[(i + 5) >> 3] >> ((i + 5) & 7)) & 1), (byte)((Random[(i + 6) >> 3] >> ((i + 6) & 7)) & 1), (byte)((Random[(i + 7) >> 3] >> ((i + 7) & 7)) & 1));
#	elif defined(__AVX__)
			r.Load((byte)((Random[i >> 3] >> (i & 7)) & 1), (byte)((Random[(i + 1) >> 3] >> ((i + 1) & 7)) & 1), (byte)((Random[(i + 2) >> 3] >> ((i + 2) & 7)) & 1), (byte)((Random[(i + 3) >> 3] >> ((i + 3) & 7)) & 1));
#	endif 

			t0.LoadT(V, i);
			t1.LoadT(V, i + 256);
			t2.LoadT(V, i + 512);
			t3.LoadT(V, i + 768);

			k = F<T>(v0[0], v1[0], N8 * t0 + N4 * r, Q);
			k += F<T>(v0[1], v1[1], N8 * t1 + N4 * r, Q);
			k += F<T>(v0[2], v1[2], N8 * t2 + N4 * r, Q);
			k += F<T>(v0[3], v1[3], N8 * t3 + N4 * r, Q);
			k = T::ShiftRA((N2 * NQ - N1 - k), 31);

			tmpV[0] = ((~k) & v0[0]) ^ (k & v1[0]);
			tmpV[1] = ((~k) & v0[1]) ^ (k & v1[1]);
			tmpV[2] = ((~k) & v0[2]) ^ (k & v1[2]);
			tmpV[3] = ((~k) & v0[3]) ^ (k & v1[3]);

			c0 = (tmpV[0] - tmpV[3]) & N3;
			c1 = (tmpV[1] - tmpV[3]) & N3;
			c2 = (tmpV[2] - tmpV[3]) & N3;
			c3 = (T::Negate(k) + N2 * tmpV[3]) & N3;

			c0.Store(tmpC, 0);
			c1.Store(tmpC, VCTSZE);
			c2.Store(tmpC, VCTSZE * 2);
			c3.Store(tmpC, VCTSZE * 3);

			for (uint j = tmpC.size() - 1, k = 0; k < VCTSZE; --j, ++k)
			{
				C[i + k + 768] = static_cast<ushort>(tmpC[j]);
				C[i + k + 512] = static_cast<ushort>(tmpC[j - VCTSZE]);
				C[i + k + 256] = static_cast<ushort>(tmpC[j - (VCTSZE * 2)]);
				C[i + k] = static_cast<ushort>(tmpC[j - (VCTSZE * 3)]);
			}
		}

#else
		std::vector<int> v0(4);
		std::vector<int> v1(4);
		std::vector<uint> tmpV(4);
		int k, x;
		byte rbit;

		for (size_t i = 0; i < V.size() / 4; i++)
		{
			rbit = (Random[i >> 3] >> (i & 7)) & 1;

			x = 8 * V[0 + i] + 4 * rbit;
			k = F<int>(v0[0], v1[0], x, Q);
			x = 8 * V[256 + i] + 4 * rbit;
			k += F<int>(v0[1], v1[1], x, Q);
			x = 8 * V[512 + i] + 4 * rbit;
			k += F<int>(v0[2], v1[2], x, Q);
			x = 8 * V[768 + i] + 4 * rbit;
			k += F<int>(v0[3], v1[3], x, Q);
			k = (2 * Q - 1 - k) >> 31;

			tmpV[0] = ((~k) & v0[0]) ^ (k & v1[0]);
			tmpV[1] = ((~k) & v0[1]) ^ (k & v1[1]);
			tmpV[2] = ((~k) & v0[2]) ^ (k & v1[2]);
			tmpV[3] = ((~k) & v0[3]) ^ (k & v1[3]);

			C[0 + i] = (tmpV[0] - tmpV[3]) & 3;
			C[256 + i] = (tmpV[1] - tmpV[3]) & 3;
			C[512 + i] = (tmpV[2] - tmpV[3]) & 3;
			C[768 + i] = (-k + 2 * tmpV[3]) & 3;
		}
#endif
	}

	template <class T>
	inline static T LdDecode(T &X0, T &X1, T &X2, T &X3, const int Q)
	{
		T t;

		t = G<T>(X0, Q);
		t += G<T>(X1, Q);
		t += G<T>(X2, Q);
		t += G<T>(X3, Q);
		t -= T(8) * T(Q);
		t >>= 31;
		t &= T(1);

		return t;
	}

	template <class T>
	inline static void Rec(std::vector<byte> &Key, const std::vector<ushort> &V, const std::vector<ushort> &C, const int Q)
	{
		Utility::MemUtils::Clear(Key, 0, Key.size());

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)

		const T NQ(Q);
		const T N2(2);
		const T N8(8);
		const T N16(16);
		const size_t VCTSZE = T::size() / sizeof(uint);

		T c0, c1, c2, c3;
		T v0, v1, v2, v3;
		std::vector<T> tmpV(4);
		std::vector<uint> tmpK(VCTSZE);

		for (size_t i = 0; i < V.size() / 4; i += VCTSZE)
		{
			c0.LoadT(C, i);
			c1.LoadT(C, 256 + i);
			c2.LoadT(C, 512 + i);
			c3.LoadT(C, 768 + i);

			v0.LoadT(V, i);
			v1.LoadT(V, 256 + i);
			v2.LoadT(V, 512 + i);
			v3.LoadT(V, 768 + i);

			tmpV[0] = N16 * NQ + N8 * v0 - NQ * (N2 * c0 + c3);
			tmpV[1] = N16 * NQ + N8 * v1 - NQ * (N2 * c1 + c3);
			tmpV[2] = N16 * NQ + N8 * v2 - NQ * (N2 * c2 + c3);
			tmpV[3] = N16 * NQ + N8 * v3 - NQ * c3;

			T K = LdDecode<T>(tmpV[0], tmpV[1], tmpV[2], tmpV[3], Q);

			K.Store(tmpK, 0);

			for (uint j = VCTSZE, k = 0; j > 0; --j, ++k)
				Key[((i + k) >> 3)] |= (byte)(tmpK[j - 1] << ((i + k) & 7));
		}

#else

		std::vector<int> tmp(4);
		for (uint i = 0; i < 256; i++)
		{
			tmp[0] = 16 * Q + 8 * (int)V[0 + i] - Q * (2 * C[0 + i] + C[768 + i]);
			tmp[1] = 16 * Q + 8 * (int)V[256 + i] - Q * (2 * C[256 + i] + C[768 + i]);
			tmp[2] = 16 * Q + 8 * (int)V[512 + i] - Q * (2 * C[512 + i] + C[768 + i]);
			tmp[3] = 16 * Q + 8 * (int)V[768 + i] - Q * (C[768 + i]);
			Key[i >> 3] |= LdDecode<int>(tmp[0], tmp[1], tmp[2], tmp[3], Q) << (i & 7);
		}
#endif
	}
};

NAMESPACE_RINGLWEEND
#endif

