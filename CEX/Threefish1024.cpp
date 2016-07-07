#include "Threefish1024.h"

void Threefish1024::Clear()
{
	if (m_expandedKey.size() > 0)
		fill(m_expandedKey.begin(), m_expandedKey.end(), 0);
	if (m_expandedTweak.size() > 0)
		fill(m_expandedTweak.begin(), m_expandedTweak.end(), 0);
}

void Threefish1024::Encrypt(const std::vector<ulong> &Input, std::vector<ulong> &Output)
{
	// cache the block, key, and tweak
	ulong B0 = Input[0];
	ulong B1 = Input[1];
	ulong B2 = Input[2];
	ulong B3 = Input[3];
	ulong B4 = Input[4];
	ulong B5 = Input[5];
	ulong B6 = Input[6];
	ulong B7 = Input[7];
	ulong B8 = Input[8];
	ulong B9 = Input[9];
	ulong B10 = Input[10];
	ulong B11 = Input[11];
	ulong B12 = Input[12];
	ulong B13 = Input[13];
	ulong B14 = Input[14];
	ulong B15 = Input[15];
	ulong K0 = m_expandedKey[0];
	ulong K1 = m_expandedKey[1];
	ulong K2 = m_expandedKey[2];
	ulong K3 = m_expandedKey[3];
	ulong K4 = m_expandedKey[4];
	ulong K5 = m_expandedKey[5];
	ulong K6 = m_expandedKey[6];
	ulong K7 = m_expandedKey[7];
	ulong K8 = m_expandedKey[8];
	ulong K9 = m_expandedKey[9];
	ulong K10 = m_expandedKey[10];
	ulong K11 = m_expandedKey[11];
	ulong K12 = m_expandedKey[12];
	ulong K13 = m_expandedKey[13];
	ulong K14 = m_expandedKey[14];
	ulong K15 = m_expandedKey[15];
	ulong K16 = m_expandedKey[16];
	ulong T0 = m_expandedTweak[0];
	ulong T1 = m_expandedTweak[1];
	ulong T2 = m_expandedTweak[2];

	Mix(B0, B1, 24, K0, K1);
	Mix(B2, B3, 13, K2, K3);
	Mix(B4, B5, 8, K4, K5);
	Mix(B6, B7, 47, K6, K7);
	Mix(B8, B9, 8, K8, K9);
	Mix(B10, B11, 17, K10, K11);
	Mix(B12, B13, 22, K12, K13 + T0);
	Mix(B14, B15, 37, K14 + T1, K15);
	Mix(B0, B9, 38);
	Mix(B2, B13, 19);
	Mix(B6, B11, 10);
	Mix(B4, B15, 55);
	Mix(B10, B7, 49);
	Mix(B12, B3, 18);
	Mix(B14, B5, 23);
	Mix(B8, B1, 52);
	Mix(B0, B7, 33);
	Mix(B2, B5, 4);
	Mix(B4, B3, 51);
	Mix(B6, B1, 13);
	Mix(B12, B15, 34);
	Mix(B14, B13, 41);
	Mix(B8, B11, 59);
	Mix(B10, B9, 17);
	Mix(B0, B15, 5);
	Mix(B2, B11, 20);
	Mix(B6, B13, 48);
	Mix(B4, B9, 41);
	Mix(B14, B1, 47);
	Mix(B8, B5, 28);
	Mix(B10, B3, 16);
	Mix(B12, B7, 25);
	Mix(B0, B1, 41, K1, K2);
	Mix(B2, B3, 9, K3, K4);
	Mix(B4, B5, 37, K5, K6);
	Mix(B6, B7, 31, K7, K8);
	Mix(B8, B9, 12, K9, K10);
	Mix(B10, B11, 47, K11, K12);
	Mix(B12, B13, 44, K13, K14 + T1);
	Mix(B14, B15, 30, K15 + T2, K16 + 1);
	Mix(B0, B9, 16);
	Mix(B2, B13, 34);
	Mix(B6, B11, 56);
	Mix(B4, B15, 51);
	Mix(B10, B7, 4);
	Mix(B12, B3, 53);
	Mix(B14, B5, 42);
	Mix(B8, B1, 41);
	Mix(B0, B7, 31);
	Mix(B2, B5, 44);
	Mix(B4, B3, 47);
	Mix(B6, B1, 46);
	Mix(B12, B15, 19);
	Mix(B14, B13, 42);
	Mix(B8, B11, 44);
	Mix(B10, B9, 25);
	Mix(B0, B15, 9);
	Mix(B2, B11, 48);
	Mix(B6, B13, 35);
	Mix(B4, B9, 52);
	Mix(B14, B1, 23);
	Mix(B8, B5, 31);
	Mix(B10, B3, 37);
	Mix(B12, B7, 20);
	Mix(B0, B1, 24, K2, K3);
	Mix(B2, B3, 13, K4, K5);
	Mix(B4, B5, 8, K6, K7);
	Mix(B6, B7, 47, K8, K9);
	Mix(B8, B9, 8, K10, K11);
	Mix(B10, B11, 17, K12, K13);
	Mix(B12, B13, 22, K14, K15 + T2);
	Mix(B14, B15, 37, K16 + T0, K0 + 2);
	Mix(B0, B9, 38);
	Mix(B2, B13, 19);
	Mix(B6, B11, 10);
	Mix(B4, B15, 55);
	Mix(B10, B7, 49);
	Mix(B12, B3, 18);
	Mix(B14, B5, 23);
	Mix(B8, B1, 52);
	Mix(B0, B7, 33);
	Mix(B2, B5, 4);
	Mix(B4, B3, 51);
	Mix(B6, B1, 13);
	Mix(B12, B15, 34);
	Mix(B14, B13, 41);
	Mix(B8, B11, 59);
	Mix(B10, B9, 17);
	Mix(B0, B15, 5);
	Mix(B2, B11, 20);
	Mix(B6, B13, 48);
	Mix(B4, B9, 41);
	Mix(B14, B1, 47);
	Mix(B8, B5, 28);
	Mix(B10, B3, 16);
	Mix(B12, B7, 25);
	Mix(B0, B1, 41, K3, K4);
	Mix(B2, B3, 9, K5, K6);
	Mix(B4, B5, 37, K7, K8);
	Mix(B6, B7, 31, K9, K10);
	Mix(B8, B9, 12, K11, K12);
	Mix(B10, B11, 47, K13, K14);
	Mix(B12, B13, 44, K15, K16 + T0);
	Mix(B14, B15, 30, K0 + T1, K1 + 3);
	Mix(B0, B9, 16);
	Mix(B2, B13, 34);
	Mix(B6, B11, 56);
	Mix(B4, B15, 51);
	Mix(B10, B7, 4);
	Mix(B12, B3, 53);
	Mix(B14, B5, 42);
	Mix(B8, B1, 41);
	Mix(B0, B7, 31);
	Mix(B2, B5, 44);
	Mix(B4, B3, 47);
	Mix(B6, B1, 46);
	Mix(B12, B15, 19);
	Mix(B14, B13, 42);
	Mix(B8, B11, 44);
	Mix(B10, B9, 25);
	Mix(B0, B15, 9);
	Mix(B2, B11, 48);
	Mix(B6, B13, 35);
	Mix(B4, B9, 52);
	Mix(B14, B1, 23);
	Mix(B8, B5, 31);
	Mix(B10, B3, 37);
	Mix(B12, B7, 20);
	Mix(B0, B1, 24, K4, K5);
	Mix(B2, B3, 13, K6, K7);
	Mix(B4, B5, 8, K8, K9);
	Mix(B6, B7, 47, K10, K11);
	Mix(B8, B9, 8, K12, K13);
	Mix(B10, B11, 17, K14, K15);
	Mix(B12, B13, 22, K16, K0 + T1);
	Mix(B14, B15, 37, K1 + T2, K2 + 4);
	Mix(B0, B9, 38);
	Mix(B2, B13, 19);
	Mix(B6, B11, 10);
	Mix(B4, B15, 55);
	Mix(B10, B7, 49);
	Mix(B12, B3, 18);
	Mix(B14, B5, 23);
	Mix(B8, B1, 52);
	Mix(B0, B7, 33);
	Mix(B2, B5, 4);
	Mix(B4, B3, 51);
	Mix(B6, B1, 13);
	Mix(B12, B15, 34);
	Mix(B14, B13, 41);
	Mix(B8, B11, 59);
	Mix(B10, B9, 17);
	Mix(B0, B15, 5);
	Mix(B2, B11, 20);
	Mix(B6, B13, 48);
	Mix(B4, B9, 41);
	Mix(B14, B1, 47);
	Mix(B8, B5, 28);
	Mix(B10, B3, 16);
	Mix(B12, B7, 25);
	Mix(B0, B1, 41, K5, K6);
	Mix(B2, B3, 9, K7, K8);
	Mix(B4, B5, 37, K9, K10);
	Mix(B6, B7, 31, K11, K12);
	Mix(B8, B9, 12, K13, K14);
	Mix(B10, B11, 47, K15, K16);
	Mix(B12, B13, 44, K0, K1 + T2);
	Mix(B14, B15, 30, K2 + T0, K3 + 5);
	Mix(B0, B9, 16);
	Mix(B2, B13, 34);
	Mix(B6, B11, 56);
	Mix(B4, B15, 51);
	Mix(B10, B7, 4);
	Mix(B12, B3, 53);
	Mix(B14, B5, 42);
	Mix(B8, B1, 41);
	Mix(B0, B7, 31);
	Mix(B2, B5, 44);
	Mix(B4, B3, 47);
	Mix(B6, B1, 46);
	Mix(B12, B15, 19);
	Mix(B14, B13, 42);
	Mix(B8, B11, 44);
	Mix(B10, B9, 25);
	Mix(B0, B15, 9);
	Mix(B2, B11, 48);
	Mix(B6, B13, 35);
	Mix(B4, B9, 52);
	Mix(B14, B1, 23);
	Mix(B8, B5, 31);
	Mix(B10, B3, 37);
	Mix(B12, B7, 20);
	Mix(B0, B1, 24, K6, K7);
	Mix(B2, B3, 13, K8, K9);
	Mix(B4, B5, 8, K10, K11);
	Mix(B6, B7, 47, K12, K13);
	Mix(B8, B9, 8, K14, K15);
	Mix(B10, B11, 17, K16, K0);
	Mix(B12, B13, 22, K1, K2 + T0);
	Mix(B14, B15, 37, K3 + T1, K4 + 6);
	Mix(B0, B9, 38);
	Mix(B2, B13, 19);
	Mix(B6, B11, 10);
	Mix(B4, B15, 55);
	Mix(B10, B7, 49);
	Mix(B12, B3, 18);
	Mix(B14, B5, 23);
	Mix(B8, B1, 52);
	Mix(B0, B7, 33);
	Mix(B2, B5, 4);
	Mix(B4, B3, 51);
	Mix(B6, B1, 13);
	Mix(B12, B15, 34);
	Mix(B14, B13, 41);
	Mix(B8, B11, 59);
	Mix(B10, B9, 17);
	Mix(B0, B15, 5);
	Mix(B2, B11, 20);
	Mix(B6, B13, 48);
	Mix(B4, B9, 41);
	Mix(B14, B1, 47);
	Mix(B8, B5, 28);
	Mix(B10, B3, 16);
	Mix(B12, B7, 25);
	Mix(B0, B1, 41, K7, K8);
	Mix(B2, B3, 9, K9, K10);
	Mix(B4, B5, 37, K11, K12);
	Mix(B6, B7, 31, K13, K14);
	Mix(B8, B9, 12, K15, K16);
	Mix(B10, B11, 47, K0, K1);
	Mix(B12, B13, 44, K2, K3 + T1);
	Mix(B14, B15, 30, K4 + T2, K5 + 7);
	Mix(B0, B9, 16);
	Mix(B2, B13, 34);
	Mix(B6, B11, 56);
	Mix(B4, B15, 51);
	Mix(B10, B7, 4);
	Mix(B12, B3, 53);
	Mix(B14, B5, 42);
	Mix(B8, B1, 41);
	Mix(B0, B7, 31);
	Mix(B2, B5, 44);
	Mix(B4, B3, 47);
	Mix(B6, B1, 46);
	Mix(B12, B15, 19);
	Mix(B14, B13, 42);
	Mix(B8, B11, 44);
	Mix(B10, B9, 25);
	Mix(B0, B15, 9);
	Mix(B2, B11, 48);
	Mix(B6, B13, 35);
	Mix(B4, B9, 52);
	Mix(B14, B1, 23);
	Mix(B8, B5, 31);
	Mix(B10, B3, 37);
	Mix(B12, B7, 20);
	Mix(B0, B1, 24, K8, K9);
	Mix(B2, B3, 13, K10, K11);
	Mix(B4, B5, 8, K12, K13);
	Mix(B6, B7, 47, K14, K15);
	Mix(B8, B9, 8, K16, K0);
	Mix(B10, B11, 17, K1, K2);
	Mix(B12, B13, 22, K3, K4 + T2);
	Mix(B14, B15, 37, K5 + T0, K6 + 8);
	Mix(B0, B9, 38);
	Mix(B2, B13, 19);
	Mix(B6, B11, 10);
	Mix(B4, B15, 55);
	Mix(B10, B7, 49);
	Mix(B12, B3, 18);
	Mix(B14, B5, 23);
	Mix(B8, B1, 52);
	Mix(B0, B7, 33);
	Mix(B2, B5, 4);
	Mix(B4, B3, 51);
	Mix(B6, B1, 13);
	Mix(B12, B15, 34);
	Mix(B14, B13, 41);
	Mix(B8, B11, 59);
	Mix(B10, B9, 17);
	Mix(B0, B15, 5);
	Mix(B2, B11, 20);
	Mix(B6, B13, 48);
	Mix(B4, B9, 41);
	Mix(B14, B1, 47);
	Mix(B8, B5, 28);
	Mix(B10, B3, 16);
	Mix(B12, B7, 25);
	Mix(B0, B1, 41, K9, K10);
	Mix(B2, B3, 9, K11, K12);
	Mix(B4, B5, 37, K13, K14);
	Mix(B6, B7, 31, K15, K16);
	Mix(B8, B9, 12, K0, K1);
	Mix(B10, B11, 47, K2, K3);
	Mix(B12, B13, 44, K4, K5 + T0);
	Mix(B14, B15, 30, K6 + T1, K7 + 9);
	Mix(B0, B9, 16);
	Mix(B2, B13, 34);
	Mix(B6, B11, 56);
	Mix(B4, B15, 51);
	Mix(B10, B7, 4);
	Mix(B12, B3, 53);
	Mix(B14, B5, 42);
	Mix(B8, B1, 41);
	Mix(B0, B7, 31);
	Mix(B2, B5, 44);
	Mix(B4, B3, 47);
	Mix(B6, B1, 46);
	Mix(B12, B15, 19);
	Mix(B14, B13, 42);
	Mix(B8, B11, 44);
	Mix(B10, B9, 25);
	Mix(B0, B15, 9);
	Mix(B2, B11, 48);
	Mix(B6, B13, 35);
	Mix(B4, B9, 52);
	Mix(B14, B1, 23);
	Mix(B8, B5, 31);
	Mix(B10, B3, 37);
	Mix(B12, B7, 20);
	Mix(B0, B1, 24, K10, K11);
	Mix(B2, B3, 13, K12, K13);
	Mix(B4, B5, 8, K14, K15);
	Mix(B6, B7, 47, K16, K0);
	Mix(B8, B9, 8, K1, K2);
	Mix(B10, B11, 17, K3, K4);
	Mix(B12, B13, 22, K5, K6 + T1);
	Mix(B14, B15, 37, K7 + T2, K8 + 10);
	Mix(B0, B9, 38);
	Mix(B2, B13, 19);
	Mix(B6, B11, 10);
	Mix(B4, B15, 55);
	Mix(B10, B7, 49);
	Mix(B12, B3, 18);
	Mix(B14, B5, 23);
	Mix(B8, B1, 52);
	Mix(B0, B7, 33);
	Mix(B2, B5, 4);
	Mix(B4, B3, 51);
	Mix(B6, B1, 13);
	Mix(B12, B15, 34);
	Mix(B14, B13, 41);
	Mix(B8, B11, 59);
	Mix(B10, B9, 17);
	Mix(B0, B15, 5);
	Mix(B2, B11, 20);
	Mix(B6, B13, 48);
	Mix(B4, B9, 41);
	Mix(B14, B1, 47);
	Mix(B8, B5, 28);
	Mix(B10, B3, 16);
	Mix(B12, B7, 25);
	Mix(B0, B1, 41, K11, K12);
	Mix(B2, B3, 9, K13, K14);
	Mix(B4, B5, 37, K15, K16);
	Mix(B6, B7, 31, K0, K1);
	Mix(B8, B9, 12, K2, K3);
	Mix(B10, B11, 47, K4, K5);
	Mix(B12, B13, 44, K6, K7 + T2);
	Mix(B14, B15, 30, K8 + T0, K9 + 11);
	Mix(B0, B9, 16);
	Mix(B2, B13, 34);
	Mix(B6, B11, 56);
	Mix(B4, B15, 51);
	Mix(B10, B7, 4);
	Mix(B12, B3, 53);
	Mix(B14, B5, 42);
	Mix(B8, B1, 41);
	Mix(B0, B7, 31);
	Mix(B2, B5, 44);
	Mix(B4, B3, 47);
	Mix(B6, B1, 46);
	Mix(B12, B15, 19);
	Mix(B14, B13, 42);
	Mix(B8, B11, 44);
	Mix(B10, B9, 25);
	Mix(B0, B15, 9);
	Mix(B2, B11, 48);
	Mix(B6, B13, 35);
	Mix(B4, B9, 52);
	Mix(B14, B1, 23);
	Mix(B8, B5, 31);
	Mix(B10, B3, 37);
	Mix(B12, B7, 20);
	Mix(B0, B1, 24, K12, K13);
	Mix(B2, B3, 13, K14, K15);
	Mix(B4, B5, 8, K16, K0);
	Mix(B6, B7, 47, K1, K2);
	Mix(B8, B9, 8, K3, K4);
	Mix(B10, B11, 17, K5, K6);
	Mix(B12, B13, 22, K7, K8 + T0);
	Mix(B14, B15, 37, K9 + T1, K10 + 12);
	Mix(B0, B9, 38);
	Mix(B2, B13, 19);
	Mix(B6, B11, 10);
	Mix(B4, B15, 55);
	Mix(B10, B7, 49);
	Mix(B12, B3, 18);
	Mix(B14, B5, 23);
	Mix(B8, B1, 52);
	Mix(B0, B7, 33);
	Mix(B2, B5, 4);
	Mix(B4, B3, 51);
	Mix(B6, B1, 13);
	Mix(B12, B15, 34);
	Mix(B14, B13, 41);
	Mix(B8, B11, 59);
	Mix(B10, B9, 17);
	Mix(B0, B15, 5);
	Mix(B2, B11, 20);
	Mix(B6, B13, 48);
	Mix(B4, B9, 41);
	Mix(B14, B1, 47);
	Mix(B8, B5, 28);
	Mix(B10, B3, 16);
	Mix(B12, B7, 25);
	Mix(B0, B1, 41, K13, K14);
	Mix(B2, B3, 9, K15, K16);
	Mix(B4, B5, 37, K0, K1);
	Mix(B6, B7, 31, K2, K3);
	Mix(B8, B9, 12, K4, K5);
	Mix(B10, B11, 47, K6, K7);
	Mix(B12, B13, 44, K8, K9 + T1);
	Mix(B14, B15, 30, K10 + T2, K11 + 13);
	Mix(B0, B9, 16);
	Mix(B2, B13, 34);
	Mix(B6, B11, 56);
	Mix(B4, B15, 51);
	Mix(B10, B7, 4);
	Mix(B12, B3, 53);
	Mix(B14, B5, 42);
	Mix(B8, B1, 41);
	Mix(B0, B7, 31);
	Mix(B2, B5, 44);
	Mix(B4, B3, 47);
	Mix(B6, B1, 46);
	Mix(B12, B15, 19);
	Mix(B14, B13, 42);
	Mix(B8, B11, 44);
	Mix(B10, B9, 25);
	Mix(B0, B15, 9);
	Mix(B2, B11, 48);
	Mix(B6, B13, 35);
	Mix(B4, B9, 52);
	Mix(B14, B1, 23);
	Mix(B8, B5, 31);
	Mix(B10, B3, 37);
	Mix(B12, B7, 20);
	Mix(B0, B1, 24, K14, K15);
	Mix(B2, B3, 13, K16, K0);
	Mix(B4, B5, 8, K1, K2);
	Mix(B6, B7, 47, K3, K4);
	Mix(B8, B9, 8, K5, K6);
	Mix(B10, B11, 17, K7, K8);
	Mix(B12, B13, 22, K9, K10 + T2);
	Mix(B14, B15, 37, K11 + T0, K12 + 14);
	Mix(B0, B9, 38);
	Mix(B2, B13, 19);
	Mix(B6, B11, 10);
	Mix(B4, B15, 55);
	Mix(B10, B7, 49);
	Mix(B12, B3, 18);
	Mix(B14, B5, 23);
	Mix(B8, B1, 52);
	Mix(B0, B7, 33);
	Mix(B2, B5, 4);
	Mix(B4, B3, 51);
	Mix(B6, B1, 13);
	Mix(B12, B15, 34);
	Mix(B14, B13, 41);
	Mix(B8, B11, 59);
	Mix(B10, B9, 17);
	Mix(B0, B15, 5);
	Mix(B2, B11, 20);
	Mix(B6, B13, 48);
	Mix(B4, B9, 41);
	Mix(B14, B1, 47);
	Mix(B8, B5, 28);
	Mix(B10, B3, 16);
	Mix(B12, B7, 25);
	Mix(B0, B1, 41, K15, K16);
	Mix(B2, B3, 9, K0, K1);
	Mix(B4, B5, 37, K2, K3);
	Mix(B6, B7, 31, K4, K5);
	Mix(B8, B9, 12, K6, K7);
	Mix(B10, B11, 47, K8, K9);
	Mix(B12, B13, 44, K10, K11 + T0);
	Mix(B14, B15, 30, K12 + T1, K13 + 15);
	Mix(B0, B9, 16);
	Mix(B2, B13, 34);
	Mix(B6, B11, 56);
	Mix(B4, B15, 51);
	Mix(B10, B7, 4);
	Mix(B12, B3, 53);
	Mix(B14, B5, 42);
	Mix(B8, B1, 41);
	Mix(B0, B7, 31);
	Mix(B2, B5, 44);
	Mix(B4, B3, 47);
	Mix(B6, B1, 46);
	Mix(B12, B15, 19);
	Mix(B14, B13, 42);
	Mix(B8, B11, 44);
	Mix(B10, B9, 25);
	Mix(B0, B15, 9);
	Mix(B2, B11, 48);
	Mix(B6, B13, 35);
	Mix(B4, B9, 52);
	Mix(B14, B1, 23);
	Mix(B8, B5, 31);
	Mix(B10, B3, 37);
	Mix(B12, B7, 20);
	Mix(B0, B1, 24, K16, K0);
	Mix(B2, B3, 13, K1, K2);
	Mix(B4, B5, 8, K3, K4);
	Mix(B6, B7, 47, K5, K6);
	Mix(B8, B9, 8, K7, K8);
	Mix(B10, B11, 17, K9, K10);
	Mix(B12, B13, 22, K11, K12 + T1);
	Mix(B14, B15, 37, K13 + T2, K14 + 16);
	Mix(B0, B9, 38);
	Mix(B2, B13, 19);
	Mix(B6, B11, 10);
	Mix(B4, B15, 55);
	Mix(B10, B7, 49);
	Mix(B12, B3, 18);
	Mix(B14, B5, 23);
	Mix(B8, B1, 52);
	Mix(B0, B7, 33);
	Mix(B2, B5, 4);
	Mix(B4, B3, 51);
	Mix(B6, B1, 13);
	Mix(B12, B15, 34);
	Mix(B14, B13, 41);
	Mix(B8, B11, 59);
	Mix(B10, B9, 17);
	Mix(B0, B15, 5);
	Mix(B2, B11, 20);
	Mix(B6, B13, 48);
	Mix(B4, B9, 41);
	Mix(B14, B1, 47);
	Mix(B8, B5, 28);
	Mix(B10, B3, 16);
	Mix(B12, B7, 25);
	Mix(B0, B1, 41, K0, K1);
	Mix(B2, B3, 9, K2, K3);
	Mix(B4, B5, 37, K4, K5);
	Mix(B6, B7, 31, K6, K7);
	Mix(B8, B9, 12, K8, K9);
	Mix(B10, B11, 47, K10, K11);
	Mix(B12, B13, 44, K12, K13 + T2);
	Mix(B14, B15, 30, K14 + T0, K15 + 17);
	Mix(B0, B9, 16);
	Mix(B2, B13, 34);
	Mix(B6, B11, 56);
	Mix(B4, B15, 51);
	Mix(B10, B7, 4);
	Mix(B12, B3, 53);
	Mix(B14, B5, 42);
	Mix(B8, B1, 41);
	Mix(B0, B7, 31);
	Mix(B2, B5, 44);
	Mix(B4, B3, 47);
	Mix(B6, B1, 46);
	Mix(B12, B15, 19);
	Mix(B14, B13, 42);
	Mix(B8, B11, 44);
	Mix(B10, B9, 25);
	Mix(B0, B15, 9);
	Mix(B2, B11, 48);
	Mix(B6, B13, 35);
	Mix(B4, B9, 52);
	Mix(B14, B1, 23);
	Mix(B8, B5, 31);
	Mix(B10, B3, 37);
	Mix(B12, B7, 20);
	Mix(B0, B1, 24, K1, K2);
	Mix(B2, B3, 13, K3, K4);
	Mix(B4, B5, 8, K5, K6);
	Mix(B6, B7, 47, K7, K8);
	Mix(B8, B9, 8, K9, K10);
	Mix(B10, B11, 17, K11, K12);
	Mix(B12, B13, 22, K13, K14 + T0);
	Mix(B14, B15, 37, K15 + T1, K16 + 18);
	Mix(B0, B9, 38);
	Mix(B2, B13, 19);
	Mix(B6, B11, 10);
	Mix(B4, B15, 55);
	Mix(B10, B7, 49);
	Mix(B12, B3, 18);
	Mix(B14, B5, 23);
	Mix(B8, B1, 52);
	Mix(B0, B7, 33);
	Mix(B2, B5, 4);
	Mix(B4, B3, 51);
	Mix(B6, B1, 13);
	Mix(B12, B15, 34);
	Mix(B14, B13, 41);
	Mix(B8, B11, 59);
	Mix(B10, B9, 17);
	Mix(B0, B15, 5);
	Mix(B2, B11, 20);
	Mix(B6, B13, 48);
	Mix(B4, B9, 41);
	Mix(B14, B1, 47);
	Mix(B8, B5, 28);
	Mix(B10, B3, 16);
	Mix(B12, B7, 25);
	Mix(B0, B1, 41, K2, K3);
	Mix(B2, B3, 9, K4, K5);
	Mix(B4, B5, 37, K6, K7);
	Mix(B6, B7, 31, K8, K9);
	Mix(B8, B9, 12, K10, K11);
	Mix(B10, B11, 47, K12, K13);
	Mix(B12, B13, 44, K14, K15 + T1);
	Mix(B14, B15, 30, K16 + T2, K0 + 19);
	Mix(B0, B9, 16);
	Mix(B2, B13, 34);
	Mix(B6, B11, 56);
	Mix(B4, B15, 51);
	Mix(B10, B7, 4);
	Mix(B12, B3, 53);
	Mix(B14, B5, 42);
	Mix(B8, B1, 41);
	Mix(B0, B7, 31);
	Mix(B2, B5, 44);
	Mix(B4, B3, 47);
	Mix(B6, B1, 46);
	Mix(B12, B15, 19);
	Mix(B14, B13, 42);
	Mix(B8, B11, 44);
	Mix(B10, B9, 25);
	Mix(B0, B15, 9);
	Mix(B2, B11, 48);
	Mix(B6, B13, 35);
	Mix(B4, B9, 52);
	Mix(B14, B1, 23);
	Mix(B8, B5, 31);
	Mix(B10, B3, 37);
	Mix(B12, B7, 20);

	// final key schedule
	Output[0] = B0 + K3;
	Output[1] = B1 + K4;
	Output[2] = B2 + K5;
	Output[3] = B3 + K6;
	Output[4] = B4 + K7;
	Output[5] = B5 + K8;
	Output[6] = B6 + K9;
	Output[7] = B7 + K10;
	Output[8] = B8 + K11;
	Output[9] = B9 + K12;
	Output[10] = B10 + K13;
	Output[11] = B11 + K14;
	Output[12] = B12 + K15;
	Output[13] = B13 + K16 + T2;
	Output[14] = B14 + K0 + T0;
	Output[15] = B15 + K1 + 20;
}

void Threefish1024::SetKey(const std::vector<ulong> &Key)
{
	size_t i;
	ulong parity = KeyScheduleConst;

	for (i = 0; i < m_expandedKey.size() - 1; i++)
	{
		m_expandedKey[i] = Key[i];
		parity ^= Key[i];
	}

	m_expandedKey[i] = parity;
}

void Threefish1024::SetTweak(const std::vector<ulong> &Tweak)
{
	m_expandedTweak[0] = Tweak[0];
	m_expandedTweak[1] = Tweak[1];
	m_expandedTweak[2] = Tweak[0] ^ Tweak[1];
}