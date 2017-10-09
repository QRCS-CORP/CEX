#ifndef _CEX_NTTN512Q25601_H
#define _CEX_NTTN512Q25601_H

#include "CexDomain.h"
#include "IntUtils.h"
#include "IPrng.h"
#include "MemUtils.h"
#include "PolyMath.h"

NAMESPACE_RINGLWE


/// <summary>
/// 
/// </summary>
class NTTN512Q25601
{
private:

#define FFTLONG uint_fast32_t
#define PRIuFFTLONG PRIuFAST32
#define FFTSHORT uint_fast16_t
#define PRIuFFTSHORT PRIuFAST16
#define RINGELT FFTSHORT
#define PRIuRINGELT PRIuFFTSHORT
#define HAVEVALIDMQ 1
#define MISPOWEROFTWO 1
#define RANDOM_VARS

/*Parameters*/
static const RINGELT m = 512, muwords = 8; /* key (mu) is m bits */
static const RINGELT q = 25601, qmod4 = 1;
static const RINGELT B = 5, BB = 11, LOG2B = 4, BMASK = 0xf;
const RINGELT small_coeff_table[11] = { 25596, 25597, 25598, 25599, 25600, 0, 1, 2, 3, 4, 5 };
static const RINGELT q_1_4 = 6400, q_2_4 = 12800, q_3_4 = 19201;
static const RINGELT r0_l = 9600, r0_u = 22401, r1_l = 3199, r1_u = 16001;
/*Set n and q*/
static const FFTSHORT n = 512;

	const FFTSHORT W[512] = { 1, 114, 12996, 22287, 6219, 17739, 25368, 24640, 18451, 4132, 10230, 14175, 3087, 19105, 1885, 10082, 22904, 25355, 23158, 3109, 21613, 6186, 13977, 6116, 5997, 18032, 7568, 17919, 20287, 8628, 10754, 22709, 3125, 23437, 9314, 12155, 3216, 8210, 14304, 17793, 5923, 9596, 18702, 7145, 20899, 1593, 2395, 17020, 20205, 24881, 20324, 12846, 5187, 2495, 2819, 14154, 693, 2199, 20277, 7488, 8799, 4647, 17738, 25254, 11644, 21765, 23514, 18092, 14408, 4048, 654, 23354, 25453, 8729, 22268, 4053, 1224, 11531, 8883, 14223, 8559, 2888, 22020, 1382, 3942, 14171, 2631, 18323, 15141, 10807, 3150, 686, 1401, 6108, 5085, 16468, 8479, 19369, 6380, 10492, 18442, 3106, 21271, 18400, 23919, 13060, 3982, 18731, 10451, 13768, 7891, 3539, 19431, 13448, 22613, 17782, 4669, 20246, 3954, 15539, 4977, 4156, 12966, 18867, 354, 14755, 18005, 4490, 25441, 7361, 19922, 18220, 3399, 3471, 11679, 154, 17556, 4506, 1664, 10489, 18100, 15320, 5612, 25344, 21904, 13759, 6865, 14580, 23656, 8679, 16568, 19879, 13318, 7793, 17968, 272, 5407, 1974, 20228, 1902, 12020, 13427, 20219, 876, 23061, 17652, 15450, 20432, 25158, 700, 2997, 8845, 9891, 1130, 815, 16107, 18527, 12796, 25088, 18321, 14913, 10416, 9778, 13849, 17125, 6574, 7007, 5167, 215, 24510, 3631, 4318, 5833, 24937, 1107, 23794, 24411, 17946, 23365, 1106, 23680, 11415, 21260, 17146, 8968, 23913, 12376, 2809, 13014, 24339, 9738, 9289, 9305, 11129, 14257, 12435, 9535, 11748, 8020, 18245, 6249, 21159, 5632, 2023, 213, 24282, 3240, 10946, 18996, 15060, 1573, 115, 13110, 9682, 2905, 23958, 17506, 24407, 17490, 22583, 14362, 24405, 17262, 22192, 20990, 11967, 7385, 22658, 22912, 666, 24722, 2198, 20163, 20093, 12113, 24029, 25600, 25487, 12605, 3314, 19382, 7862, 233, 961, 7150, 21469, 15371, 11426, 22514, 6496, 23716, 15519, 2697, 246, 2443, 22492, 3988, 19415, 11624, 19485, 19604, 7569, 18033, 7682, 5314, 16973, 14847, 2892, 22476, 2164, 16287, 13446, 22385, 17391, 11297, 7808, 19678, 16005, 6899, 18456, 4702, 24008, 23206, 8581, 5396, 720, 5277, 12755, 20414, 23106, 22782, 11447, 24908, 23402, 5324, 18113, 16802, 20954, 7863, 347, 13957, 3836, 2087, 7509, 11193, 21553, 24947, 2247, 148, 16872, 3333, 21548, 24377, 14070, 16718, 11378, 17042, 22713, 3581, 24219, 21659, 11430, 22970, 7278, 10460, 14794, 22451, 24915, 24200, 19493, 20516, 9133, 17122, 6232, 19221, 15109, 7159, 22495, 4330, 7201, 1682, 12541, 21619, 6870, 15150, 11833, 17710, 22062, 6170, 12153, 2988, 7819, 20932, 5355, 21647, 10062, 20624, 21445, 12635, 6734, 25247, 10846, 7596, 21111, 160, 18240, 5679, 7381, 22202, 22130, 13922, 25447, 8045, 21095, 23937, 15112, 7501, 10281, 19989, 257, 3697, 11842, 18736, 11021, 1945, 16922, 9033, 5722, 12283, 17808, 7633, 25329, 20194, 23627, 5373, 23699, 13581, 12174, 5382, 24725, 2540, 7949, 10151, 5169, 443, 24901, 22604, 16756, 15710, 24471, 24786, 9494, 7074, 12805, 513, 7280, 10688, 15185, 15823, 11752, 8476, 19027, 18594, 20434, 25386, 1091, 21970, 21283, 19768, 664, 24494, 1807, 1190, 7655, 2236, 24495, 1921, 14186, 4341, 8455, 16633, 1688, 13225, 22792, 12587, 1262, 15863, 16312, 16296, 14472, 11344, 13166, 16066, 13853, 17581, 7356, 19352, 4442, 19969, 23578, 25388, 1319, 22361, 14655, 6605, 10541, 24028, 25486, 12491, 15919, 22696, 1643, 8095, 1194, 8111, 3018, 11239, 1196, 8339, 3409, 4611, 13634, 18216, 2943, 2689, 24935, 879, 23403, 5438, 5508, 13488, 1572 };

	const FFTSHORT W_rev[512] = { 1, 1572, 13488, 5508, 5438, 23403, 879, 24935, 2689, 2943, 18216, 13634, 4611, 3409, 8339, 1196, 11239, 3018, 8111, 1194, 8095, 1643, 22696, 15919, 12491, 25486, 24028, 10541, 6605, 14655, 22361, 1319, 25388, 23578, 19969, 4442, 19352, 7356, 17581, 13853, 16066, 13166, 11344, 14472, 16296, 16312, 15863, 1262, 12587, 22792, 13225, 1688, 16633, 8455, 4341, 14186, 1921, 24495, 2236, 7655, 1190, 1807, 24494, 664, 19768, 21283, 21970, 1091, 25386, 20434, 18594, 19027, 8476, 11752, 15823, 15185, 10688, 7280, 513, 12805, 7074, 9494, 24786, 24471, 15710, 16756, 22604, 24901, 443, 5169, 10151, 7949, 2540, 24725, 5382, 12174, 13581, 23699, 5373, 23627, 20194, 25329, 7633, 17808, 12283, 5722, 9033, 16922, 1945, 11021, 18736, 11842, 3697, 257, 19989, 10281, 7501, 15112, 23937, 21095, 8045, 25447, 13922, 22130, 22202, 7381, 5679, 18240, 160, 21111, 7596, 10846, 25247, 6734, 12635, 21445, 20624, 10062, 21647, 5355, 20932, 7819, 2988, 12153, 6170, 22062, 17710, 11833, 15150, 6870, 21619, 12541, 1682, 7201, 4330, 22495, 7159, 15109, 19221, 6232, 17122, 9133, 20516, 19493, 24200, 24915, 22451, 14794, 10460, 7278, 22970, 11430, 21659, 24219, 3581, 22713, 17042, 11378, 16718, 14070, 24377, 21548, 3333, 16872, 148, 2247, 24947, 21553, 11193, 7509, 2087, 3836, 13957, 347, 7863, 20954, 16802, 18113, 5324, 23402, 24908, 11447, 22782, 23106, 20414, 12755, 5277, 720, 5396, 8581, 23206, 24008, 4702, 18456, 6899, 16005, 19678, 7808, 11297, 17391, 22385, 13446, 16287, 2164, 22476, 2892, 14847, 16973, 5314, 7682, 18033, 7569, 19604, 19485, 11624, 19415, 3988, 22492, 2443, 246, 2697, 15519, 23716, 6496, 22514, 11426, 15371, 21469, 7150, 961, 233, 7862, 19382, 3314, 12605, 25487, 25600, 24029, 12113, 20093, 20163, 2198, 24722, 666, 22912, 22658, 7385, 11967, 20990, 22192, 17262, 24405, 14362, 22583, 17490, 24407, 17506, 23958, 2905, 9682, 13110, 115, 1573, 15060, 18996, 10946, 3240, 24282, 213, 2023, 5632, 21159, 6249, 18245, 8020, 11748, 9535, 12435, 14257, 11129, 9305, 9289, 9738, 24339, 13014, 2809, 12376, 23913, 8968, 17146, 21260, 11415, 23680, 1106, 23365, 17946, 24411, 23794, 1107, 24937, 5833, 4318, 3631, 24510, 215, 5167, 7007, 6574, 17125, 13849, 9778, 10416, 14913, 18321, 25088, 12796, 18527, 16107, 815, 1130, 9891, 8845, 2997, 700, 25158, 20432, 15450, 17652, 23061, 876, 20219, 13427, 12020, 1902, 20228, 1974, 5407, 272, 17968, 7793, 13318, 19879, 16568, 8679, 23656, 14580, 6865, 13759, 21904, 25344, 5612, 15320, 18100, 10489, 1664, 4506, 17556, 154, 11679, 3471, 3399, 18220, 19922, 7361, 25441, 4490, 18005, 14755, 354, 18867, 12966, 4156, 4977, 15539, 3954, 20246, 4669, 17782, 22613, 13448, 19431, 3539, 7891, 13768, 10451, 18731, 3982, 13060, 23919, 18400, 21271, 3106, 18442, 10492, 6380, 19369, 8479, 16468, 5085, 6108, 1401, 686, 3150, 10807, 15141, 18323, 2631, 14171, 3942, 1382, 22020, 2888, 8559, 14223, 8883, 11531, 1224, 4053, 22268, 8729, 25453, 23354, 654, 4048, 14408, 18092, 23514, 21765, 11644, 25254, 17738, 4647, 8799, 7488, 20277, 2199, 693, 14154, 2819, 2495, 5187, 12846, 20324, 24881, 20205, 17020, 2395, 1593, 20899, 7145, 18702, 9596, 5923, 17793, 14304, 8210, 3216, 12155, 9314, 23437, 3125, 22709, 10754, 8628, 20287, 17919, 7568, 18032, 5997, 6116, 13977, 6186, 21613, 3109, 23158, 25355, 22904, 10082, 1885, 19105, 3087, 14175, 10230, 4132, 18451, 24640, 25368, 17739, 6219, 22287, 12996, 114 };

	const FFTSHORT W_sqrt[256] = { 22188, 20534, 11185, 20641, 23383, 3158, 1598, 2965, 5197, 3635, 4774, 6615, 11681, 382, 17947, 23479, 14102, 20366, 17634, 13398, 16913, 8007, 16763, 16508, 13039, 1588, 1825, 3242, 11174, 19387, 8432, 14011, 9992, 12644, 7760, 14206, 6621, 12365, 1555, 23664, 9591, 18132, 18968, 11868, 21700, 16104, 18185, 25010, 9429, 25265, 12898, 11115, 12661, 9698, 4729, 1485, 15684, 21507, 19703, 18855, 24587, 12409, 6571, 6665, 17381, 10157, 5853, 1616, 5017, 8716, 20786, 14312, 18705, 7487, 8685, 17252, 21052, 19035, 19506, 21998, 24475, 25242, 10276, 19419, 12080, 20267, 6348, 6844, 12186, 6750, 1470, 13974, 5774, 18211, 2373, 14512, 15904, 20986, 11511, 6603, 10313, 23637, 6513, 53, 6042, 23162, 3565, 22395, 18531, 13252, 269, 5065, 14188, 4569, 8846, 10005, 14126, 23102, 22326, 10665, 12563, 24127, 11171, 19045, 20646, 23953, 16936, 10629, 8459, 17089, 2470, 25570, 22067, 6740, 330, 12019, 13313, 7223, 4190, 16842, 25514, 15683, 21393, 6707, 22169, 18368, 20271, 6804, 7626, 24531, 6025, 21224, 13042, 1930, 15212, 18901, 4230, 21402, 7733, 11128, 14143, 25040, 12849, 5529, 15882, 18478, 7210, 2708, 1500, 17394, 11639, 21195, 9736, 9061, 8914, 17757, 1819, 2558, 10001, 13670, 22320, 9981, 11390, 18410, 25059, 15015, 22044, 4118, 8634, 11438, 23882, 8842, 9549, 13344, 10757, 23051, 16512, 13495, 2370, 14170, 2517, 5327, 18455, 4588, 11012, 919, 2362, 13258, 953, 6238, 19905, 16282, 12876, 8607, 8360, 5803, 21517, 20843, 20810, 17048, 23397, 4754, 4335, 7771, 15460, 21572, 1512, 18762, 13985, 7028, 7561, 17121, 6118, 6225, 18423, 940, 4756, 4563, 8162, 8832, 8409, 11389, 18296, 12063, 18329, 15825, 11980, 8867, 12399, 5431, 4710, 24920, 24770, 7670, 3946, 14627 };

	const FFTSHORT W_sqrt_rev[256] = { 10974, 21655, 17931, 831, 681, 20891, 20170, 13202, 16734, 13621, 9776, 7272, 13538, 7305, 14212, 17192, 16769, 17439, 21038, 20845, 24661, 7178, 19376, 19483, 8480, 18040, 18573, 11616, 6839, 24089, 4029, 10141, 17830, 21266, 20847, 2204, 8553, 4791, 4758, 4084, 19798, 17241, 16994, 12725, 9319, 5696, 19363, 24648, 12343, 23239, 24682, 14589, 21013, 7146, 20274, 23084, 11431, 23231, 12106, 9089, 2550, 14844, 12257, 16052, 16759, 1719, 14163, 16967, 21483, 3557, 10586, 542, 7191, 14211, 15620, 3281, 11931, 15600, 23043, 23782, 7844, 16687, 16540, 15865, 4406, 13962, 8207, 24101, 22893, 18391, 7123, 9719, 20072, 12752, 561, 11458, 14473, 17868, 4199, 21371, 6700, 10389, 23671, 12559, 4377, 19576, 1070, 17975, 18797, 5330, 7233, 3432, 18894, 4208, 9918, 87, 8759, 21411, 18378, 12288, 13582, 25271, 18861, 3534, 31, 23131, 8512, 17142, 14972, 8665, 1648, 4955, 6556, 14430, 1474, 13038, 14936, 3275, 2499, 11475, 15596, 16755, 21032, 11413, 20536, 25332, 12349, 7070, 3206, 22036, 2439, 19559, 25548, 19088, 1964, 15288, 18998, 14090, 4615, 9697, 11089, 23228, 7390, 19827, 11627, 24131, 18851, 13415, 18757, 19253, 5334, 13521, 6182, 15325, 359, 1126, 3603, 6095, 6566, 4549, 8349, 16916, 18114, 6896, 11289, 4815, 16885, 20584, 23985, 19748, 15444, 8220, 18936, 19030, 13192, 1014, 6746, 5898, 4094, 9917, 24116, 20872, 15903, 12940, 14486, 12703, 336, 16172, 591, 7416, 9497, 3901, 13733, 6633, 7469, 16010, 1937, 24046, 13236, 18980, 11395, 17841, 12957, 15609, 11590, 17169, 6214, 14427, 22359, 23776, 24013, 12562, 9093, 8838, 17594, 8688, 12203, 7967, 5235, 11499, 2122, 7654, 25219, 13920, 18986, 20827, 21966, 20404, 22636, 24003, 22443, 2218, 4960, 14416, 5067, 3413 };

#define RANDOM8 ((uint8_t) rand())
#define RANDOM32 ((uint32_t) (rand() << 16) ^ rand())
#define RANDOM64 (((uint64_t) RANDOM32 << (uint64_t) 32) | ((uint64_t) RANDOM32))

/*Use the twisted Fourier Transform in the Power of 2 case for multiplication
in the ring F_q[x] / <x^m+1>*/
#define FFT_forward FFT_twisted_forward_512_25601
#define FFT_backward(_x)\
	do {\
		FFT_twisted_backward_512_25601(_x);\
		for (uint16_t _i = 0; _i < m; ++_i) {\
			MUL_MOD((_x)[_i], (_x)[_i], 25551, (q));\
		}\
	} while(0)

#define ADD_MOD(x, a, b, q) \
do {\
	x = (a) + (b);\
	x -= (x >= (q)) ? (q) : 0;\
} while (0)	


#define ADD(x, a, b) \
do {\
	x = (a) + (b);\
} while (0)	


#define MOD(x, q) \
do {\
	x = x % (q);\
} while (0)	


#define SUB_MOD(x, a, b, q) \
do {\
	x = (a) + ((q) - (b));\
	x -= (x >= (q)) ? (q) : 0;\
} while (0)

/*Needed for indexing in the FFT*/
#define SUB_MODn(x, a, b) \
do {\
	x = (a) + (n-(b));\
	x -= (x >= n) ? n : 0;\
} while (0)

#define MUL_MOD(x, a, b, q) \
do {\
	FFTLONG x64 = (FFTLONG) (a)*(b);\
	x64 = x64 % (q);\
	x = (FFTSHORT) x64;\
} while(0)
/*v = e0*b, multiply and add in the ring. All done in the FFT / CRT domain, so point-wise multiplication and addition*/
#define POINTWISE_MUL(v, b, e0) \
do {\
	for (uint16_t _i = 0; _i < m; ++_i) {\
		MUL_MOD((v)[_i], (e0)[_i], (b)[_i], (q));\
	}\
} while(0)

/*v = e0+b, multiply and add in the ring. All done in the FFT / CRT domain, so point-wise multiplication and addition*/
#define POINTWISE_ADD(v, b, e0) \
do {\
	for (uint16_t _i = 0; _i < m; ++_i) {\
		ADD_MOD((v)[_i], (e0)[_i], (b)[_i], (q));\
	}\
} while(0)


/*v = e0*b+e1, multiply and add in the ring. All done in the FFT / CRT domain, so point-wise multiplication and addition*/
#define POINTWISE_MUL_ADD(v, b, e0, e1) \
do {\
	for (uint16_t _i = 0; _i < m; ++_i) {\
		MUL_MOD((v)[_i], (e0)[_i], (b)[_i], (q));\
		ADD_MOD((v)[_i], (v)[_i], (e1)[_i], (q));\
	}\
} while(0)


/*Map a length m object in the ring F_q[x]/<x^m-1> to a length m-1 object in the ring F_q[x]/<1+x+...+x^{m-1}>*/
#if MISPOWEROFTWO	
#define MAPTOCYCLOTOMIC(v)
#else
#define MAPTOCYCLOTOMIC(v) \
	do {\
		for (uint16_t _i = 0; _i < m-1; ++_i) {\
			SUB_MOD((v)[_i], (v)[_i], (v)[m-1], q);\
		}\
		v[m-1] = 0;\
	} while(0)
#endif

	/* Public Parameter a. Each a parameter rejection sampled from non-overlapping
	* segments of the digits of e.
	* Note that this is held in the FFT / CRT basis.*/
	const RINGELT a[512] = {
		0x3A5B, 0x163F, 0x0989, 0x155A, 0x2E98, 0x5946, 0x371B, 0x22DE,
		0x344E, 0x0B8B, 0x1FEF, 0x5C6D, 0x45BE, 0x5930, 0x59E3, 0x3977,
		0x2F78, 0x3B06, 0x2E09, 0x5C31, 0x5A1D, 0x4092, 0x45A7, 0x4D30,
		0x2EE7, 0x443C, 0x00D1, 0x296C, 0x3B88, 0x4E51, 0x3863, 0x2967,
		0x5E9C, 0x11FC, 0x22D5, 0x2ABB, 0x2D33, 0x2523, 0x4F69, 0x3CAA,
		0x4424, 0x56BC, 0x55E8, 0x0192, 0x532F, 0x005E, 0x0457, 0x256E,
		0x30D7, 0x1D4F, 0x50CA, 0x1619, 0x5C16, 0x2D9F, 0x5466, 0x35C3,
		0x4364, 0x33BE, 0x508C, 0x58E1, 0x2D45, 0x3D94, 0x2F83, 0x2C97,
		0x3BDE, 0x511C, 0x4B08, 0x52E9, 0x5C1D, 0x60B4, 0x47E8, 0x4B12,
		0x04BA, 0x340F, 0x46F3, 0x4581, 0x52A5, 0x3ED0, 0x130E, 0x6012,
		0x3964, 0x186F, 0x2622, 0x36E0, 0x4BF8, 0x4EE1, 0x5204, 0x37E7,
		0x22AF, 0x08B7, 0x05AA, 0x12DA, 0x2EE1, 0x4D00, 0x0BA8, 0x22FC,
		0x54C8, 0x49A8, 0x2154, 0x2933, 0x3A48, 0x6191, 0x06DC, 0x5007,
		0x3916, 0x0B43, 0x3BB6, 0x23C4, 0x5ED6, 0x498A, 0x4B70, 0x5C88,
		0x601B, 0x5DC4, 0x0F92, 0x1964, 0x1959, 0x4795, 0x54B5, 0x5F57,
		0x5B43, 0x5C5B, 0x6066, 0x1E99, 0x6128, 0x2C19, 0x110E, 0x2CEB,
		0x3F42, 0x1BB3, 0x536F, 0x19A5, 0x1B34, 0x4629, 0x4993, 0x5EB9,
		0x114E, 0x4782, 0x5D17, 0x56AC, 0x3392, 0x1AE0, 0x38B5, 0x1FF2,
		0x4DD6, 0x636E, 0x1A78, 0x15C0, 0x1D91, 0x31C0, 0x3658, 0x404F,
		0x536A, 0x5120, 0x0428, 0x2A24, 0x03CE, 0x4EB8, 0x0395, 0x0B70,
		0x2C0E, 0x35E6, 0x4542, 0x3766, 0x1D78, 0x1AFA, 0x1A42, 0x30AC,
		0x0CA4, 0x298B, 0x1109, 0x0F3D, 0x55AC, 0x5314, 0x2F0A, 0x5B1B,
		0x2D98, 0x0B7E, 0x21E3, 0x59D9, 0x5FF9, 0x0815, 0x4239, 0x3F48,
		0x1F14, 0x4267, 0x1F3F, 0x1A8C, 0x0F13, 0x4F3B, 0x01A0, 0x0C03,
		0x0F43, 0x534F, 0x2FE0, 0x06F6, 0x3270, 0x3207, 0x2137, 0x2AE4,
		0x025A, 0x600D, 0x008D, 0x31F8, 0x449A, 0x5381, 0x07BB, 0x23DC,
		0x349A, 0x1884, 0x6312, 0x37E9, 0x3A1F, 0x00A2, 0x5179, 0x1DB6,
		0x1F53, 0x3220, 0x40FA, 0x15CF, 0x57CD, 0x3EC4, 0x248A, 0x018B,
		0x5AA2, 0x423A, 0x0F3F, 0x0956, 0x2452, 0x4BA7, 0x0DEC, 0x4D7D,
		0x4967, 0x2FA5, 0x4BF6, 0x3746, 0x4811, 0x16E9, 0x42C8, 0x2347,
		0x1875, 0x3CCD, 0x1E50, 0x0D5F, 0x0427, 0x613E, 0x4C1C, 0x1517,
		0x5241, 0x3612, 0x1F40, 0x0043, 0x31BF, 0x2E95, 0x5050, 0x410C,
		0x21C0, 0x4462, 0x2B4D, 0x1982, 0x4300, 0x59EC, 0x590A, 0x1697,
		0x4D25, 0x18BE, 0x000E, 0x3B02, 0x5A52, 0x5F55, 0x0336, 0x2900,
		0x21FE, 0x3CE6, 0x2FF1, 0x343E, 0x4F90, 0x34D1, 0x48C2, 0x0BF8,
		0x1AE5, 0x1C33, 0x061A, 0x454B, 0x33EC, 0x1BA2, 0x3340, 0x4DA4,
		0x3393, 0x5E32, 0x498A, 0x1273, 0x500F, 0x2B16, 0x0811, 0x3F7C,
		0x2854, 0x2812, 0x4E04, 0x00BE, 0x11B5, 0x0466, 0x140B, 0x2900,
		0x31D4, 0x20EE, 0x2379, 0x14DF, 0x4642, 0x6194, 0x551B, 0x5571,
		0x5A28, 0x1D71, 0x05D4, 0x4A67, 0x1BA5, 0x5EE3, 0x62CF, 0x2742,
		0x53DB, 0x083C, 0x5C1E, 0x0717, 0x1319, 0x37A9, 0x3E20, 0x2867,
		0x0F3D, 0x6296, 0x5B76, 0x5A4C, 0x2CFF, 0x2B92, 0x5440, 0x2A73,
		0x5C53, 0x5E4D, 0x5292, 0x480C, 0x2341, 0x3DD5, 0x363E, 0x6270,
		0x21BF, 0x3FA0, 0x6285, 0x191C, 0x267D, 0x37E2, 0x1B15, 0x63D3,
		0x13E8, 0x4DA3, 0x6051, 0x217F, 0x53F1, 0x63CC, 0x2CB9, 0x6153,
		0x3BEB, 0x01CE, 0x62B4, 0x13D4, 0x5CB9, 0x37AE, 0x0743, 0x5257,
		0x1D81, 0x4BC9, 0x52E2, 0x013E, 0x166F, 0x5B44, 0x4B45, 0x4A26,
		0x6207, 0x21E6, 0x3C77, 0x03DB, 0x4EC6, 0x49D2, 0x1C92, 0x0DDD,
		0x380F, 0x634D, 0x3C1F, 0x5D73, 0x51DD, 0x2C68, 0x5E8D, 0x32D3,
		0x309A, 0x54F7, 0x4332, 0x056D, 0x59DF, 0x4469, 0x411C, 0x0D98,
		0x471C, 0x1B6A, 0x1541, 0x303A, 0x1F21, 0x0B6C, 0x2338, 0x2EFC,
		0x3554, 0x614F, 0x0F13, 0x2B48, 0x5108, 0x0344, 0x1E65, 0x2050,
		0x194F, 0x2690, 0x59A8, 0x5D6E, 0x2A9A, 0x0DA9, 0x09C5, 0x505E,
		0x096F, 0x3573, 0x3F7E, 0x4BD1, 0x4C07, 0x5E51, 0x4534, 0x53AC,
		0x4137, 0x3B7B, 0x54CF, 0x010A, 0x187B, 0x3BE9, 0x30F0, 0x53AB,
		0x2431, 0x3FA4, 0x3EAB, 0x04E4, 0x0478, 0x14CC, 0x2F1A, 0x36CA,
		0x591F, 0x0FEA, 0x3800, 0x4C58, 0x27AE, 0x6081, 0x0CE9, 0x324B,
		0x5DCA, 0x2358, 0x5EDC, 0x20AD, 0x34F8, 0x5ADD, 0x21CF, 0x2C70,
		0x1483, 0x0972, 0x155C, 0x11E9, 0x5591, 0x5C85, 0x43C9, 0x08AC,
		0x3886, 0x4331, 0x564E, 0x0AB7, 0x40DF, 0x3006, 0x0549, 0x618E,
		0x473E, 0x05F4, 0x13BB, 0x2FFD, 0x61AF, 0x1C76, 0x369C, 0x2002,
		0x3C7F, 0x55E2, 0x10B2, 0x03EC, 0x0273, 0x60D5, 0x0DF7, 0x1285,
		0x4F29, 0x14DE, 0x61DD, 0x5435, 0x110F, 0x60D4, 0x0D75, 0x27C3,
		0x3F5B, 0x0CFA, 0x0A5B, 0x2FF6, 0x0CAC, 0x4EC5, 0x1BF9, 0x24B5
	};

	const uint64_t rlwe_table[52][3] = {
		{ 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x1FFFFFFFFFFFFFFF },
		{ 0xE0C81DA0D6A8BD22, 0x161ABD186DA13542, 0x5CEF2C248806C827 },
		{ 0x8D026C4E14BC7408, 0x4344C125B3533F22, 0x9186506BCC065F20 },
		{ 0x10AC7CEC7D7E2A3B, 0x5D62CE65E6217813, 0xBAAB5F82BCDB43B3 },
		{ 0x709C92996E94D801, 0x1411F551608E4D22, 0xD7D9769FAD23BCB1 },
		{ 0x6287D827008404B7, 0x7E1526D618902F20, 0xEA9BE2F4D6DDB5ED },
		{ 0x34CBDC118C15F40E, 0xE7D2A13787E94674, 0xF58A99474919B8C9 },
		{ 0xD521F7EBBBE8C3A2, 0xE8A773D9A1EA0AAB, 0xFB5117812753B7B8 },
		{ 0xC3D9E58131089A6A, 0x148CB49FF716491B, 0xFE151BD0928596D3 },
		{ 0x2E060C4A842A27F6, 0x07E44D009ADB0049, 0xFF487508BA9F7208 },
		{ 0xFCEDEFCFAA887582, 0x1A5409BF5D4B039E, 0xFFC16686270CFC82 },
		{ 0x4FE22E5DF9FAAC20, 0xFDC99BFE0F991958, 0xFFEC8AC3C159431B },
		{ 0xA36605F81B14FEDF, 0xA6FCD4C13F4AFCE0, 0xFFFA7DF4B6E92C28 },
		{ 0x9D1FDCFF97BBC957, 0x4B869C6286ED0BB5, 0xFFFE94BB4554B5AC },
		{ 0x6B3EEBA74AAD104B, 0xEC72329E974D63C7, 0xFFFFAADE1B1CAA95 },
		{ 0x48C8DA4009C10760, 0x337F6316C1FF0A59, 0xFFFFEDDC1C6436DC },
		{ 0x84480A71312F35E7, 0xD95E7B2CD6933C97, 0xFFFFFC7C9DC2569A },
		{ 0x23C01DAC1513FA0F, 0x8E0B132AE72F729F, 0xFFFFFF61BC337FED },
		{ 0x90C89D6570165907, 0x05B9D725AAEA5CAD, 0xFFFFFFE6B3CF05F7 },
		{ 0x692E2A94C500EC7D, 0x99E8F72C370F27A6, 0xFFFFFFFC53EA610E },
		{ 0x28C2998CEAE37CC8, 0xC6E2F0D7CAFA9AB8, 0xFFFFFFFF841943DE },
		{ 0xC515CF4CB0130256, 0x4745913CB4F9E4DD, 0xFFFFFFFFF12D07EC },
		{ 0x39F0ECEA047D6E3A, 0xEE62D42142AC6544, 0xFFFFFFFFFE63E348 },
		{ 0xDF11BB25B50462D6, 0x064A0C6CC136E943, 0xFFFFFFFFFFD762C7 },
		{ 0xCDBA0DD69FD2EA0F, 0xC672F3A74DB0F175, 0xFFFFFFFFFFFC5E37 },
		{ 0xFDB966A75F3604D9, 0x6ABEF8B144723D83, 0xFFFFFFFFFFFFB48F },
		{ 0x3C4FECBB600740D1, 0x697598CEADD71A15, 0xFFFFFFFFFFFFFA72 },
		{ 0x1574CC916D60E673, 0x12F5A30DD99D7051, 0xFFFFFFFFFFFFFFA1 },
		{ 0xDD3DCD1B9CB7321D, 0x4016ED3E05883572, 0xFFFFFFFFFFFFFFFA },
		{ 0xB4A4E8CF3DF79A7A, 0xAF22D9AFAD5A73CF, 0xFFFFFFFFFFFFFFFF },
		{ 0x91056A8196F74466, 0xFBF88681905332BA, 0xFFFFFFFFFFFFFFFF },
		{ 0x965B9ED9BD366C04, 0xFFD16385AF29A51F, 0xFFFFFFFFFFFFFFFF },
		{ 0xF05F75D38F2D28A3, 0xFFFE16FF8EA2B60C, 0xFFFFFFFFFFFFFFFF },
		{ 0x77E35C8980421EE8, 0xFFFFEDD3C9DDC7E8, 0xFFFFFFFFFFFFFFFF },
		{ 0x92783617956F140A, 0xFFFFFF63392B6E8F, 0xFFFFFFFFFFFFFFFF },
		{ 0xA536DC994639AD78, 0xFFFFFFFB3592B3D1, 0xFFFFFFFFFFFFFFFF },
		{ 0x8F3A871874DD9FD5, 0xFFFFFFFFDE04A5BB, 0xFFFFFFFFFFFFFFFF },
		{ 0x310DE3650170B717, 0xFFFFFFFFFF257152, 0xFFFFFFFFFFFFFFFF },
		{ 0x1F21A853A422F8CC, 0xFFFFFFFFFFFB057B, 0xFFFFFFFFFFFFFFFF },
		{ 0x3CA9D5C6DB4EE2BA, 0xFFFFFFFFFFFFE5AD, 0xFFFFFFFFFFFFFFFF },
		{ 0xCFD9CE958E59869C, 0xFFFFFFFFFFFFFF81, 0xFFFFFFFFFFFFFFFF },
		{ 0xDB8E1F91D955C452, 0xFFFFFFFFFFFFFFFD, 0xFFFFFFFFFFFFFFFF },
		{ 0xF78EE3A8E99E08C3, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
		{ 0xFFE1D7858BABDA25, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
		{ 0xFFFF9E52E32CAB4A, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
		{ 0xFFFFFEE13217574F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
		{ 0xFFFFFFFD04888041, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
		{ 0xFFFFFFFFF8CD8A56, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
		{ 0xFFFFFFFFFFF04111, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
		{ 0xFFFFFFFFFFFFE0C5, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
		{ 0xFFFFFFFFFFFFFFC7, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF },
		{ 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF }
	};


	/*
	We use Gentleman-Sande, decimation-in-frequency FFT, for the forward FFT.
	Note that we will not perform the usual scambling / bit-reversal procedure here because we will invert
	the fourier transform using decimation-in-time.
	*/
	void FFT_forward_512_25601(FFTSHORT x[512]) {
		FFTSHORT index, step;
		FFTSHORT i, j, m;
		FFTSHORT t0, t1;

		step = 1;
		for (m = n >> 1; m >= 1; m = m >> 1) {
			index = 0;
			for (j = 0; j < m; ++j) {
				for (i = j; i < n; i += (m << 1)) {
					ADD_MOD(t0, x[i], x[i + m], q);
					ADD(t1, x[i], q - x[i + m]);
					MUL_MOD(x[i + m], t1, W[index], q);
					x[i] = t0;
				}
				SUB_MODn(index, index, step);
			}
			step = step << 1;
		}
	}

	/*
	We use Cooley-Tukey, decimation-in-time FFT, for the inverse FFT.
	Note that we will not perform the usual scambling / bit-reversal procedure here because we will the forward
	fourier transform is using decimation-in-frequency.
	*/
	void FFT_backward_512_25601(FFTSHORT x[512]) {
		FFTSHORT index, step;
		FFTSHORT i, j, m;
		FFTSHORT t0, t1;

		step = n >> 1;
		for (m = 1; m < n; m = m << 1) {
			index = 0;
			for (j = 0; j < m; ++j) {
				for (i = j; i < n; i += (m << 1)) {
					t0 = x[i];
					t0 -= (t0 >= q) ? q : 0;
					MUL_MOD(t1, x[i + m], W_rev[index], q);
					ADD(x[i], t0, t1);
					ADD(x[i + m], t0, q - t1);

				}
				SUB_MODn(index, index, step);
			}
			step = step >> 1;
		}
		for (i = 0; i < n; ++i) {
			x[i] -= (x[i] >= q) ? q : 0;
		}
	}


	/*
	We use Gentleman-Sande, decimation-in-frequency FFT, for the forward FFT.
	We premultiply x by the 2n'th roots of unity to affect a Discrete Weighted Fourier Transform,
	so when we apply pointwise multiplication we obtain the negacyclic convolution, i.e. multiplication
	modulo x^n+1.
	Note that we will not perform the usual scambling / bit-reversal procedure here because we will invert
	the fourier transform using decimation-in-time.
	*/
	void FFT_twisted_forward_512_25601(FFTSHORT x[512]) {
		FFTSHORT index, step;
		FFTSHORT i, j, m;
		FFTSHORT t0, t1;

		//Pre multiplication for twisted FFT
		j = 0;
		for (i = 0; i < n >> 1; ++i) {
			MUL_MOD(x[j], x[j], W[i], q);
			j++;
			MUL_MOD(x[j], x[j], W_sqrt[i], q);
			j++;
		}

		step = 1;
		for (m = n >> 1; m >= 1; m = m >> 1) {
			index = 0;
			for (j = 0; j < m; ++j) {
				for (i = j; i < n; i += (m << 1)) {
					ADD_MOD(t0, x[i], x[i + m], q);
					ADD(t1, x[i], q - x[i + m]);
					MUL_MOD(x[i + m], t1, W[index], q);
					x[i] = t0;
				}
				SUB_MODn(index, index, step);
			}
			step = step << 1;
		}
	}

	/*
	We use Cooley-Tukey, decimation-in-time FFT, for the inverse FFT.
	We postmultiply x by the inverse of the 2n'th roots of unity * n^-1 to affect a Discrete Weighted Fourier Transform,
	so when we apply pointwise multiplication we obtain the negacyclic convolution, i.e. multiplication
	modulo x^n+1.
	Note that we will not perform the usual scambling / bit-reversal procedure here because we will the forward
	fourier transform is using decimation-in-frequency.
	*/
	void FFT_twisted_backward_512_25601(FFTSHORT x[512]) {
		FFTSHORT index, step;
		FFTSHORT i, j, m;
		FFTSHORT t0, t1;

		step = n >> 1;
		for (m = 1; m < n; m = m << 1) {
			index = 0;
			for (j = 0; j < m; ++j) {
				for (i = j; i < n; i += (m << 1)) {
					t0 = x[i];
					t0 -= (t0 >= q) ? q : 0;
					MUL_MOD(t1, x[i + m], W_rev[index], q);
					ADD(x[i], t0, t1);
					ADD(x[i + m], t0, q - t1);
				}
				SUB_MODn(index, index, step);
			}
			step = step >> 1;
		}

		//Post multiplication for twisted FFT
		j = 0;
		for (i = 0; i < n >> 1; ++i) {
			MUL_MOD(x[j], x[j], W_rev[i], q);
			j++;
			MUL_MOD(x[j], x[j], W_sqrt_rev[i], q);
			j++;
		}
	}


	/*O(n^2) cyclic convolution code for testing*/
	void slow_cyclic_convolution_512_25601(FFTSHORT z[512], FFTSHORT x[512], FFTSHORT y[512]) {
		FFTSHORT i, j, t;
		for (i = 0; i < n; ++i) {
			z[i] = 0;
			for (j = 0; j <= i; ++j) {
				MUL_MOD(t, x[j], y[i - j], q);
				ADD_MOD(z[i], z[i], t, q);
			}
			for (j = i + 1; j < n; ++j) {
				MUL_MOD(t, x[j], y[n + i - j], q);
				ADD_MOD(z[i], z[i], t, q);
			}
		}
	}


	/*O(nlogn) cyclic convolution*/
	void cyclic_convolution_512_25601(FFTSHORT z[512], FFTSHORT x[512], FFTSHORT y[512]) {

		FFT_forward_512_25601(x);
		FFT_forward_512_25601(y);

		FFTSHORT i;
		for (i = 0; i < n; ++i) {
			MUL_MOD(z[i], x[i], y[i], q);
		}
		FFT_backward_512_25601(z);
		/*Multiply by n^-1 mod q*/
		for (i = 0; i < n; ++i) {
			MUL_MOD(z[i], z[i], 25551UL, q);
		}
	}


	/*O(n^2) negacyclic convolution code for testing*/
	void slow_negacyclic_convolution_512_25601(FFTSHORT z[512], FFTSHORT x[512], FFTSHORT y[512]) {
		FFTSHORT i, j, t;
		for (i = 0; i < n; ++i) {
			z[i] = 0;
			for (j = 0; j <= i; ++j) {
				MUL_MOD(t, x[j], y[i - j], q);
				ADD_MOD(z[i], z[i], t, q);
			}
			for (j = i + 1; j < n; ++j) {
				MUL_MOD(t, x[j], y[n + i - j], q);
				SUB_MOD(z[i], z[i], t, q);
			}
		}
	}


	/*O(nlogn) negacyclic convolution*/
	void negacyclic_convolution_512_25601(FFTSHORT z[512], FFTSHORT x[512], FFTSHORT y[512]) {

		FFT_twisted_forward_512_25601(x);
		FFT_twisted_forward_512_25601(y);

		FFTSHORT i;
		for (i = 0; i < n; ++i) {
			MUL_MOD(z[i], x[i], y[i], q);
		}
		FFT_twisted_backward_512_25601(z);
		/*Multiply by n^-1 mod q*/
		for (i = 0; i < n; ++i) {
			MUL_MOD(z[i], z[i], 25551UL, q);
		}
	}

	Prng::IPrng* m_rndGenerator;

public:

	static const int N = 256;
	static const int Q = 7681;

	NTTN512Q25601(Prng::IPrng* Rng)
		:
		m_rndGenerator(Rng)
	{
	}

	/*
	Sample the secret key. Each coefficient uniform in [-B,B].
	Set the m'th coefficient to be 0 if m is prime.
	*/
	void sample_secret(RINGELT s[m]) 
	{
		RANDOM_VARS;
		uint16_t i = 0;
		uint64_t r = RANDOM64;
		uint64_t l, shifts = 0;

#if MISPOWEROFTWO
		while (i < m) {
#else
		while (i < m - 1) {
#endif	
			l = r & BMASK;
			if (l < BB) {
				/*Take this sample*/
				s[i] = small_coeff_table[l];
				i++;
			}
			/*Shift r along and continue*/
			shifts++;
			if (shifts * LOG2B >= 64) {
				/*Need a new random value*/
				r = RANDOM64;
				shifts = 0;
			}
			else r = (r >> LOG2B);
		}
#if !MISPOWEROFTWO
		s[m - 1] = 0;
#endif	
	}

	/* Round and cross-round */
	void round_and_cross_round(uint64_t modular_rnd[muwords], uint64_t cross_rnd[muwords], const RINGELT v[m]) 
	{
		RANDOM_VARS;
		uint16_t i = 0;
		uint64_t r = RANDOM64;
		RINGELT word = 0, pos = 0, rbit = 0, val;

		memset((void *)modular_rnd, 0, muwords * sizeof(uint64_t));
		memset((void *)cross_rnd, 0, muwords * sizeof(uint64_t));

#if MISPOWEROFTWO
		for (i = 0; i < m; ++i) {
#else	
		for (i = 0; i < m - 1; ++i) {
#endif	
			val = v[i];
			/*Randomize rounding procedure - probabilistic nudge*/
			if (qmod4 == 1) {
				if (val == 0) {
					if (r & 1) val = (q - 1);
					rbit++;
					if (rbit >= 64) {
						r = RANDOM64; rbit = 0;
					}
					else r = (r >> 1);
				}
				else if (val == q_1_4 - 1) {
					if (r & 1) val = q_1_4;
					rbit++;
					if (rbit >= 64) {
						r = RANDOM64; rbit = 0;
					}
					else r = (r >> 1);
				}
			}
			else {
				if (val == 0) {
					if (r & 1) val = (q - 1);
					rbit++;
					if (rbit >= 64) {
						r = RANDOM64; rbit = 0;
					}
					else r = (r >> 1);
				}
				else if (val == q_3_4 - 1) {
					if (r & 1) val = q_3_4;
					rbit++;
					if (rbit >= 64) {
						r = RANDOM64; rbit = 0;
					}
					else r = (r >> 1);
				}
			}

			/*Modular rounding process*/
			if (val > q_1_4 && val < q_3_4) modular_rnd[word] |= (1UL << pos);

			/*Cross Rounding process*/
			if ((val > q_1_4 && val <= q_2_4) || val >= q_3_4) cross_rnd[word] |= (1UL << pos);

			pos++;
			if (pos == 64) {
				word++; pos = 0;
			}

		}
	}


	/* Reconcile */
	void rec(uint64_t r[muwords], RINGELT w[m], uint64_t b[muwords]) 
	{
		RINGELT i = 0;
		RINGELT word = 0, pos = 0;

		memset((void *)r, 0, muwords * sizeof(uint64_t));

#if MISPOWEROFTWO
		for (i = 0; i < m; ++i) {
#else	
		for (i = 0; i < m - 1; ++i) {
#endif	
			if ((b[word] >> pos) & 1UL) {
				if (w[i] > r1_l && w[i] < r1_u) r[word] |= (1UL << pos);
			}
			else {
				if (w[i] > r0_l && w[i] < r0_u) r[word] |= (1UL << pos);
			}
			pos++;
			if (pos == 64) {
				word++; pos = 0;
			}
		}
	}

	/* Construct Alice's private / public key pair. Return all elements in the Fourier Domain
	* input:  none
	* output: private key s_1=s[n]...s[2*n-1] in Fourier Domain
	*         noise term s_0=s[0]...s[n-1] in Fourier Domain, not needed again
	*         public key b in Fourier Domain
	*/
	void KEM1_Generate(RINGELT s[2 * m], RINGELT b[m]) 
	{
		sample_secret(s);	sample_secret(s + m);
		/*Fourier Transform secret keys*/
		FFT_forward(s); FFT_forward(s + m);
		POINTWISE_MUL_ADD(b, a, s + m, s); //Combine with a to produce s_1*a+s_0 in the Fourier domain. Alice's public key.

	}

	/* Encapsulation routine. Returns an element in R_q x R_2
	* input:  Alice's public key b in Fourier Domain
	* output: Bob's public key u in Fourier Domain
	*         reconciliation data cr_v
	*         shared secret mu
	*/
	void KEM1_Encapsulate(RINGELT u[m], uint64_t cr_v[muwords], uint64_t mu[muwords], RINGELT b[m]) 
	{
		RINGELT e[3 * m];
		RINGELT v[m];

		/*Sample Bob's ephemeral keys*/
		sample_secret(e);	sample_secret(e + m); sample_secret(e + 2 * m);
		/*Fourer Transform e0 and e1*/
		FFT_forward(e); FFT_forward(e + m);
		POINTWISE_MUL_ADD(u, a, e, e + m); //Combine with a to produce e_0*a+e_1 in the Fourier domain. Bob's public key.

		POINTWISE_MUL(v, b, e); //Create v = e0*b
		FFT_backward(v); //Undo the Fourier Transform
		MAPTOCYCLOTOMIC(v);

		POINTWISE_ADD(v, v, e + 2 * m); //Create v = e0*b+e2

		round_and_cross_round(mu, cr_v, v);
	}

	/* Decapsulation routine.
	* input:  Bob's public key u in Fourier Domain
	*         Alice's private key s_1 in Fourier Domain
	*         reconciliation data cr_v
	* output: shared secret mu
	*/
	void KEM1_Decapsulate(uint64_t mu[muwords], RINGELT u[m], RINGELT s_1[m], uint64_t cr_v[muwords]) 
	{
		RINGELT w[m];

		POINTWISE_MUL(w, s_1, u); //Create w = s1*u
		FFT_backward(w); //Undo the Fourier Transform
		MAPTOCYCLOTOMIC(w);
		rec(mu, w, cr_v);
	}
};

NAMESPACE_RINGLWEEND
#endif
