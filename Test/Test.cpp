// HISTORY
//
// ### CEX 1.0.0.6 ###
// Current Release 1.0.0.6 (version A6)
// The NTRU Prime asymmetric cipher
// The RSX symmetric cipher
// Asymmetric ciphers updated to the NIST PQ Round 1 versions
//
// ### CEX 1.0.0.5 ###
// Current Release 1.0.0.5 (version A5)
// The ModuleLWE asymmetric cipher
// The SHAKE Key Derivation Function
// Addition of asymmetric cipher Encapsulate / Decapsulate api
// The library is now Misra C++ 2014 compliant
//
// ### CEX 1.0.0.4 ###
// 1.0.0.4, Full Release
// The full version will be Misra and SEI-CERT compliant, (eta. is mid December 2017)
// Added McEliece public key crypto system	-done
// Added Keccak1024 message digest	-done
// Added Poly1305 Mac and ChaCha/Poly1305 AEAD mode -(mode scheduled for 1.0.0.5)
// Reworked public classes/interfaces for POD data types in preparation for DLL interface -ongoing..
// Complete preformance optimization cycle; strategic memory allocation (stack or heap), and review class/function variables -ongoing..
// Complete security compliance cycle; all code reviewed and updated to MISRA/SEI-CERT security recommendations -ongoing..
//
// Release 1.0.0.3, June 30, 2017
// Added asymmetric cipher interfaces and framework
// Added RingLWE asymmetric cipher
// Added the Auto Collection seed Provider (ACP)
// Addition of the HCR prng
// Renaming of the drbgs to xCG format: BCG, DCG, and HCG; Block cipher Counter Generator, Digest and HMAC Counter Generators
// Overhaul of SecureRandom and prng classes
//
// Release 1.0.0.2, April 23, 2017
// Added and integrated a vectorized MemUtils class
// Added experimental AVX512 support
// Added UInt512 class
// Added MemUtils and SIMD tests
// Templated Chacha and Salsa
// Rewrites of Twofish and Serpent
// Headers are now documentation only (no inline accessors)
// Added override hint to virtual functions in headers
// Many small format changes and a couple of bug fixes
//
// Release 1.0.1.1, April 08, 2017
// Fixed a bug in CpuDetect (misreporting SIMD capabilities of some cpu's)
// Added preprocessor definitions for intrinsics throughout both projects
// Cleaned up the test project
// Changes to code required by Intel tool-chain
// Tested on Intel i3, i5, i7, and an AMD K9
// Tested on debug and release versions of ARM/x86/x64
// Tested on MSVC 2015 and 2017 ide
// Now supports arch:AVX2 (recommended), arch:AVX (minimum), or no intrinsics support, arch:IA32
// Many misc. internal todo's and rewrites completed
//
// Release 1.0.0.1
// Skein Tree			-done
// Rewrite SHA2			-done
// Rewrite Blake2		-done
// Keccak Tree			-done
// Scrypt				-done
// Code review			-done
// Help review			-done
//
// Release 0.14.2.1
// EAX/GCM/OCB			-done
// GMAC					-done
// Code review			-done
//
// Release 0.13
// HX kdf change		-done
// DCG/BCG/HCG Drbg		-done
// RDP/ECP/CJP provider -done
// Secure Key/mem		-done
// CipherStream rewrite	-done
// KeyGenerator rewrite	-dome	

// TRAJECTORY
//
// ### SCHEDULE FOR 1.0.0.7 RELEASE ###
// ## ETA is August 1, 2018 ##
// 
// Add RSA asymmetric cipher
// Add RSA signature scheme
// Add vectorized hash functions (AVX2/AVX512) for future expansion
// Add 'stitched' implementations of AHX-CBC/CTR/GCM
// Add 'stitched' implementation of ChaCha/Poly1305
//
// ### SCHEDULE FOR 1.0.0.6 RELEASE ###
// ## ETA is April 30, 2018 ##
// 
// Add cSHAKE 128/256/512/1024 DRBG -done
// Add KMAC Message Authentication Code generator -done
// Security and performance review of DRBGs and MACs -done
// Add vectorized hash functions (AVX2/AVX512) for future expansion -ongoing by 1.0.0.7
// Add 'stitched' implementations of AHX-CBC/CTR/GCM -deferred to 1.0.0.7
// Add 'stitched' implementation of ChaCha/Poly1305 -deferred to 1.0.0.7
// Multi-threaded/vectorized CMAC? -no
// Rewrite ACP/ECP (change to cSHAKE generator) -done
// Add NTRU Prime asymmetric cipher -done
//
//
// ### Planned Release 1.1.0.1 ###
//
// AVX512 integration		-started
// RingLWE					-added
// McEliece					-added
// ModuleLWE				-added
// NTRU						-added
// RSA
// RSA-Sig
// SPHINCS+
// Picnic
//
// ### Planned Release 1.2.0.1 ###
// TLS
// STM - KEX
// Android / iOS / Linux compatibility
// DLL API
//
// ## Style Rules ##
// 
// namespace: Single capaitalized word, ex. Network::
// class name: Pascal case description, maximum of two words, ex. SymmetricKey()
// function name: Pascal case, maximum of two words, ex. Initialize()
// function parameters: Pascal case, maximum of two words, ex. Initialize(ISymmetricKey &Key)
// global variable: Camel Case, with the prefix 'g_', ex. g_globalState
// class variable: Camel Case, with the prefix 'm_', ex. m_classState
// function variable: a single word or 2 Camel case words in abbreviated form, ex. ctr, or, blkCtr
// global constant: All Caps, a total of three words with the 'CEX_' prefix, ex. CEX_GLOBAL_CONSTANT
// class constant: All Caps, a total of two words, ex. CLASS_CONSTANT
// function constant: Two capitalized and abbreviated 3 letter words with no underscore divider, ex. FNCCST

#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "../CEX/CpuDetect.h"
#include "../Test/TestFiles.h"
#include "../Test/TestUtils.h"
#include "../Test/AEADTest.h"
#include "../Test/AesAvsTest.h"
#include "../Test/AesFipsTest.h"
#include "../Test/AsymmetricSpeedTest.h"
#include "../Test/BCGTest.h"
#include "../Test/Blake2Test.h"
#include "../Test/ChaChaTest.h"
#include "../Test/CipherModeTest.h"
#include "../Test/CipherSpeedTest.h"
#include "../Test/CipherStreamTest.h"
#include "../Test/CMACTest.h"
#include "../Test/ConsoleUtils.h"
#include "../Test/CSGTest.h"
#include "../Test/DigestSpeedTest.h"
#include "../Test/DigestStreamTest.h"
#include "../Test/GMACTest.h"
#include "../Test/KDF2Test.h"
#include "../Test/KeccakTest.h"
#include "../Test/KMACTest.h"
#include "../Test/HKDFTest.h"
#include "../Test/HMACTest.h"
#include "../Test/HMGTest.h"
#include "../Test/HXCipherTest.h"
#include "../Test/ITest.h"
#include "../Test/MacStreamTest.h"
#include "../Test/McElieceTest.h"
#include "../Test/MemUtilsTest.h"
#include "../Test/ModuleLWETest.h"
#include "../Test/NTRUTest.h"
#include "../Test/PaddingTest.h"
#include "../Test/ParallelModeTest.h"
#include "../Test/PBKDF2Test.h"
#include "../Test/Poly1305Test.h"
#include "../Test/PrngTest.h"
#include "../Test/RandomOutputTest.h"
#include "../Test/RijndaelTest.h"
#include "../Test/RingLWETest.h"
#include "../Test/SalsaTest.h"
#include "../Test/SCRYPTTest.h"
#include "../Test/SecureStreamTest.h"
#include "../Test/SerpentTest.h"
#include "../Test/Sha2Test.h"
#include "../Test/SimdSpeedTest.h"
#include "../Test/SimdWrapperTest.h"
#include "../Test/SHAKETest.h"
#include "../Test/SkeinTest.h"
#include "../Test/SymmetricKeyGeneratorTest.h"
#include "../Test/SymmetricKeyTest.h"
#include "../Test/TwofishTest.h"
#include "../Test/UtilityTest.h"

using namespace Test;

void CpuCheck()
{
	Common::CpuDetect detect;
	ConsoleUtils::WriteLine("L1 cache size: " + std::to_string(detect.L1CacheSize()));
	ConsoleUtils::WriteLine("Total L1 cache size: " + std::to_string(detect.L1CacheTotal()));
	ConsoleUtils::WriteLine("L1 cache line size: " + std::to_string(detect.L1CacheLineSize()));
	ConsoleUtils::WriteLine("L2 cache size: " + std::to_string(detect.L2CacheSize()));
	ConsoleUtils::WriteLine("Physical cores: " + std::to_string(detect.PhysicalCores()));
	ConsoleUtils::WriteLine("Virtual cores: " + std::to_string(detect.VirtualCores()));
	ConsoleUtils::WriteLine("HyperThreading: " + std::to_string(detect.HyperThread()));
	ConsoleUtils::WriteLine("AES-NI: " + std::to_string(detect.AESNI()));
	ConsoleUtils::WriteLine("AVX: " + std::to_string(detect.AVX()));
	ConsoleUtils::WriteLine("AVX2: " + std::to_string(detect.AVX2()));
	ConsoleUtils::WriteLine("CMUL: " + std::to_string(detect.CMUL()));
	ConsoleUtils::WriteLine("RDRAND: " + std::to_string(detect.RDRAND()));
	ConsoleUtils::WriteLine("RDTSCP: " + std::to_string(detect.RDTSCP()));
	ConsoleUtils::WriteLine("SHA: " + std::to_string(detect.SHA()));
	ConsoleUtils::WriteLine("SSE2: " + std::to_string(detect.SSE2()));
	ConsoleUtils::WriteLine("SSE3: " + std::to_string(detect.SSE3()));
	ConsoleUtils::WriteLine("SSSE3: " + std::to_string(detect.SSSE3()));
	ConsoleUtils::WriteLine("SSE41: " + std::to_string(detect.SSE41()));
	ConsoleUtils::WriteLine("SSE42: " + std::to_string(detect.SSE42()));
	ConsoleUtils::WriteLine("XOP: " + std::to_string(detect.XOP()));
	ConsoleUtils::WriteLine("");
}

std::string GetResponse()
{
	std::string resp = "";
	try
	{
		std::getline(std::cin, resp);
	}
	catch (std::exception&)
	{
	}

	return resp;
}

bool CanTest(std::string Message)
{
	ConsoleUtils::WriteLine(Message);
	std::string resp = GetResponse();
	std::transform(resp.begin(), resp.end(), resp.begin(), ::toupper);

	const std::string CONFIRM = "Y";
	bool state = false;

	if (resp.find(CONFIRM) != std::string::npos)
	{
		state = true;
	}

	return state;
}

void PrintHeader(std::string Data, std::string Decoration = "***")
{
	ConsoleUtils::WriteLine(Decoration + Data + Decoration);
}

void PrintTitle()
{
	ConsoleUtils::WriteLine("***********************************************");
	ConsoleUtils::WriteLine("* CEX++ Version 1.0.0.6: CEX Library in C++   *");
	ConsoleUtils::WriteLine("*                                             *");
	ConsoleUtils::WriteLine("* Release:   v1.0.0.6 (A6)                    *");
	ConsoleUtils::WriteLine("* License:   GPLv3                            *");
	ConsoleUtils::WriteLine("* Date:      June 17, 2018                    *");
	ConsoleUtils::WriteLine("* Contact:   develop@vtdev.com                *");
	ConsoleUtils::WriteLine("***********************************************");
	ConsoleUtils::WriteLine("");
}

void CloseApp()
{
	PrintHeader("An error has occurred! Press any key to close..", "");
	GetResponse();
	exit(0);
}

void RunTest(Test::ITest* Test)
{
	try
	{
		TestEventHandler handler;
		Test->Progress() += &handler;
		ConsoleUtils::WriteLine(Test->Description());
		ConsoleUtils::WriteLine(Test->Run());
		Test->Progress() -= &handler;
		ConsoleUtils::WriteLine("");

		delete Test;
	}
	catch (TestException &ex)
	{
		ConsoleUtils::WriteLine("An error has occured!");

		if (ex.Message().size() != 0)
		{
			ConsoleUtils::WriteLine(ex.Message());
		}

		ConsoleUtils::WriteLine("");
		ConsoleUtils::WriteLine("Continue Testing? Press 'Y' to continue, all other keys abort..");

		std::string resp;
		std::getline(std::cin, resp);
		std::transform(resp.begin(), resp.end(), resp.begin(), ::toupper);

		const std::string CONTINUE = "Y";
		if (resp.find(CONTINUE) == std::string::npos)
		{
			CloseApp();
		}
	}
}

void PrintArray(uint16_t* a, size_t row, size_t len)
{
	for (int i = 0; i < len; i++) 
	{
		printf("%d, ", a[i]);

		if (i != 0 && i % row == 0)
			printf("\n");
	}
}

void BitRevGen()
{
	uint16_t bitrev_table1[1024] = 
	{
		0, 512, 256, 768, 128, 640, 384, 896, 64, 576, 320, 832, 192, 704, 448, 960, 32, 544, 288, 800, 160, 672, 416, 928, 96, 608, 352, 864, 224, 736, 480, 992, 
		16, 528, 272, 784, 144, 656, 400, 912, 80, 592, 336, 848, 208, 720, 464, 976, 48, 560, 304, 816, 176, 688, 432, 944, 112, 624, 368, 880, 240, 752, 496, 1008, 
		8, 520, 264, 776, 136, 648, 392, 904, 72, 584, 328, 840, 200, 712, 456, 968, 40, 552, 296, 808, 168, 680, 424, 936, 104, 616, 360, 872, 232, 744, 488, 1000, 
		24, 536, 280, 792, 152, 664, 408, 920, 88, 600, 344, 856, 216, 728, 472, 984, 56, 568, 312, 824, 184, 696, 440, 952, 120, 632, 376, 888, 248, 760, 504, 1016, 
		4, 516, 260, 772, 132, 644, 388, 900, 68, 580, 324, 836, 196, 708, 452, 964, 36, 548, 292, 804, 164, 676, 420, 932, 100, 612, 356, 868, 228, 740, 484, 996, 
		20, 532, 276, 788, 148, 660, 404, 916, 84, 596, 340, 852, 212, 724, 468, 980, 52, 564, 308, 820, 180, 692, 436, 948, 116, 628, 372, 884, 244, 756, 500, 1012, 
		12, 524, 268, 780, 140, 652, 396, 908, 76, 588, 332, 844, 204, 716, 460, 972, 44, 556, 300, 812, 172, 684, 428, 940, 108, 620, 364, 876, 236, 748, 492, 1004, 
		28, 540, 284, 796, 156, 668, 412, 924, 92, 604, 348, 860, 220, 732, 476, 988, 60, 572, 316, 828, 188, 700, 444, 956, 124, 636, 380, 892, 252, 764, 508, 1020, 
		2, 514, 258, 770, 130, 642, 386, 898, 66, 578, 322, 834, 194, 706, 450, 962, 34, 546, 290, 802, 162, 674, 418, 930, 98, 610, 354, 866, 226, 738, 482, 994, 
		18, 530, 274, 786, 146, 658, 402, 914, 82, 594, 338, 850, 210, 722, 466, 978, 50, 562, 306, 818, 178, 690, 434, 946, 114, 626, 370, 882, 242, 754, 498, 1010, 
		10, 522, 266, 778, 138, 650, 394, 906, 74, 586, 330, 842, 202, 714, 458, 970, 42, 554, 298, 810, 170, 682, 426, 938, 106, 618, 362, 874, 234, 746, 490, 1002, 
		26, 538, 282, 794, 154, 666, 410, 922, 90, 602, 346, 858, 218, 730, 474, 986, 58, 570, 314, 826, 186, 698, 442, 954, 122, 634, 378, 890, 250, 762, 506, 1018, 
		6, 518, 262, 774, 134, 646, 390, 902, 70, 582, 326, 838, 198, 710, 454, 966, 38, 550, 294, 806, 166, 678, 422, 934, 102, 614, 358, 870, 230, 742, 486, 998, 
		22, 534, 278, 790, 150, 662, 406, 918, 86, 598, 342, 854, 214, 726, 470, 982, 54, 566, 310, 822, 182, 694, 438, 950, 118, 630, 374, 886, 246, 758, 502, 1014, 
		14, 526, 270, 782, 142, 654, 398, 910, 78, 590, 334, 846, 206, 718, 462, 974, 46, 558, 302, 814, 174, 686, 430, 942, 110, 622, 366, 878, 238, 750, 494, 1006, 
		30, 542, 286, 798, 158, 670, 414, 926, 94, 606, 350, 862, 222, 734, 478, 990, 62, 574, 318, 830, 190, 702, 446, 958, 126, 638, 382, 894, 254, 766, 510, 1022, 
		1, 513, 257, 769, 129, 641, 385, 897, 65, 577, 321, 833, 193, 705, 449, 961, 33, 545, 289, 801, 161, 673, 417, 929, 97, 609, 353, 865, 225, 737, 481, 993, 
		17, 529, 273, 785, 145, 657, 401, 913, 81, 593, 337, 849, 209, 721, 465, 977, 49, 561, 305, 817, 177, 689, 433, 945, 113, 625, 369, 881, 241, 753, 497, 1009, 
		9, 521, 265, 777, 137, 649, 393, 905, 73, 585, 329, 841, 201, 713, 457, 969, 41, 553, 297, 809, 169, 681, 425, 937, 105, 617, 361, 873, 233, 745, 489, 1001, 
		25, 537, 281, 793, 153, 665, 409, 921, 89, 601, 345, 857, 217, 729, 473, 985, 57, 569, 313, 825, 185, 697, 441, 953, 121, 633, 377, 889, 249, 761, 505, 1017, 
		5, 517, 261, 773, 133, 645, 389, 901, 69, 581, 325, 837, 197, 709, 453, 965, 37, 549, 293, 805, 165, 677, 421, 933, 101, 613, 357, 869, 229, 741, 485, 997, 
		21, 533, 277, 789, 149, 661, 405, 917, 85, 597, 341, 853, 213, 725, 469, 981, 53, 565, 309, 821, 181, 693, 437, 949, 117, 629, 373, 885, 245, 757, 501, 1013, 
		13, 525, 269, 781, 141, 653, 397, 909, 77, 589, 333, 845, 205, 717, 461, 973, 45, 557, 301, 813, 173, 685, 429, 941, 109, 621, 365, 877, 237, 749, 493, 1005, 
		29, 541, 285, 797, 157, 669, 413, 925, 93, 605, 349, 861, 221, 733, 477, 989, 61, 573, 317, 829, 189, 701, 445, 957, 125, 637, 381, 893, 253, 765, 509, 1021, 
		3, 515, 259, 771, 131, 643, 387, 899, 67, 579, 323, 835, 195, 707, 451, 963, 35, 547, 291, 803, 163, 675, 419, 931, 99, 611, 355, 867, 227, 739, 483, 995, 
		19, 531, 275, 787, 147, 659, 403, 915, 83, 595, 339, 851, 211, 723, 467, 979, 51, 563, 307, 819, 179, 691, 435, 947, 115, 627, 371, 883, 243, 755, 499, 1011, 
		11, 523, 267, 779, 139, 651, 395, 907, 75, 587, 331, 843, 203, 715, 459, 971, 43, 555, 299, 811, 171, 683, 427, 939, 107, 619, 363, 875, 235, 747, 491, 1003, 
		27, 539, 283, 795, 155, 667, 411, 923, 91, 603, 347, 859, 219, 731, 475, 987, 59, 571, 315, 827, 187, 699, 443, 955, 123, 635, 379, 891, 251, 763, 507, 1019, 
		7, 519, 263, 775, 135, 647, 391, 903, 71, 583, 327, 839, 199, 711, 455, 967, 39, 551, 295, 807, 167, 679, 423, 935, 103, 615, 359, 871, 231, 743, 487, 999, 
		23, 535, 279, 791, 151, 663, 407, 919, 87, 599, 343, 855, 215, 727, 471, 983, 55, 567, 311, 823, 183, 695, 439, 951, 119, 631, 375, 887, 247, 759, 503, 1015, 
		15, 527, 271, 783, 143, 655, 399, 911, 79, 591, 335, 847, 207, 719, 463, 975, 47, 559, 303, 815, 175, 687, 431, 943, 111, 623, 367, 879, 239, 751, 495, 1007, 
		31, 543, 287, 799, 159, 671, 415, 927, 95, 607, 351, 863, 223, 735, 479, 991, 63, 575, 319, 831, 191, 703, 447, 959, 127, 639, 383, 895, 255, 767, 511, 1023
	};

	uint16_t bitrev_tableb[512] =
	{
		0, 256, 128, 384, 64,  320,  192, 448, 32, 288, 160, 416, 96, 352, 224, 480, 16, 272, 144, 400, 80, 336, 208, 464, 48, 304, 176, 432, 112, 368, 240, 496, 8,
		264, 136, 392, 72, 328, 200, 456, 40, 296, 168, 424, 104, 360, 232, 488, 24, 280, 152, 408, 88, 344, 216, 472, 56, 312, 184, 440, 120, 376, 248, 504, 4,
		260, 132, 388, 68, 324, 196, 452, 36, 292, 164, 420, 100, 356, 228, 484, 20, 276, 148, 404, 84, 340, 212, 468, 52, 308, 180, 436, 116, 372, 244, 500, 12,
		268, 140, 396, 76, 332, 204, 460, 44, 300, 172, 428, 108, 364, 236, 492, 28, 284, 156, 412, 92, 348, 220, 476, 60, 316, 188, 444, 124, 380, 252, 508, 2,
		258, 130, 386, 66, 322, 194, 450, 34, 290, 162, 418, 98, 354, 226, 482, 18, 274, 146, 402, 82, 338, 210, 466, 50, 306, 178, 434, 114, 370, 242, 498, 10,
		266, 138, 394, 74, 330, 202, 458, 42, 298, 170, 426, 106, 362, 234, 490, 26, 282, 154, 410, 90, 346, 218, 474, 58, 314, 186, 442, 122, 378, 250, 506, 6,
		262, 134, 390, 70, 326, 198, 454, 38, 294, 166, 422, 102, 358, 230, 486, 22, 278, 150, 406, 86, 342, 214, 470, 54, 310, 182, 438, 118, 374, 246, 502, 14,
		270, 142, 398, 78, 334, 206, 462, 46, 302, 174, 430, 110, 366, 238, 494, 30, 286, 158, 414, 94, 350, 222, 478, 62, 318, 190, 446, 126, 382, 254, 510, 1,
		257, 129, 385, 65, 321, 193, 449, 33, 289, 161, 417, 97, 353, 225, 481, 17, 273, 145, 401, 81, 337, 209, 465, 49, 305, 177, 433, 113, 369, 241, 497, 9,
		265, 137, 393, 73, 329, 201, 457, 41, 297, 169, 425, 105, 361, 233, 489, 25, 281, 153, 409, 89, 345, 217, 473, 57, 313, 185, 441, 121, 377, 249, 505, 5,
		261, 133, 389, 69, 325, 197, 453, 37, 293, 165, 421, 101, 357, 229, 485, 21, 277, 149, 405, 85, 341, 213, 469, 53, 309, 181, 437, 117, 373, 245, 501, 13,
		269, 141, 397, 77, 333, 205, 461, 45, 301, 173, 429, 109, 365, 237, 493, 29, 285, 157, 413, 93, 349, 221, 477, 61, 317, 189, 445, 125, 381, 253, 509, 3,
		259, 131, 387, 67, 323, 195, 451, 35, 291, 163, 419, 99, 355, 227, 483, 19, 275, 147, 403, 83, 339, 211, 467, 51, 307, 179, 435, 115, 371, 243, 499, 11,
		267, 139, 395, 75, 331, 203, 459, 43, 299, 171, 427, 107, 363, 235, 491, 27, 283, 155, 411, 91, 347, 219, 475, 59, 315, 187, 443, 123, 379, 251, 507, 7,
		263, 135, 391, 71, 327, 199, 455, 39, 295, 167, 423, 103, 359, 231, 487, 23, 279, 151, 407, 87, 343, 215, 471, 55, 311, 183, 439, 119, 375, 247, 503, 15,
		271, 143, 399, 79, 335, 207, 463, 47, 303, 175, 431, 111, 367, 239, 495, 31, 287, 159, 415, 95, 351, 223, 479, 63, 319, 191, 447, 127, 383, 255, 511,
	};
	PrintArray(bitrev_tableb, 32, 512);

	uint16_t tablec[512];
	tablec[0] = 0;
	size_t T = 512;

	for (size_t i = 1; i < 512; i += 16)
	{
		tablec[i] = T / 2;				// 256
		tablec[i + 1] = T / 4;			// 128
		tablec[i + 2] = T / 4 * 3;		// 384
		tablec[i + 3] = T / 8;			// 64
		tablec[i + 4] = T / 8 * 5;		// 320
		tablec[i + 5] = T / 8 * 3;		// 192
		tablec[i + 6] = T / 8 * 7;		// 448
		tablec[i + 7] = T / 16;			// 32
		tablec[i + 8] = T / 16 * 9;		// 288
		tablec[i + 9] = T / 16 * 5;		// 160
		tablec[i + 10] = T / 16 * 13;	// 416
		tablec[i + 11] = T / 16 * 3;	// 96
		tablec[i + 12] = T / 16 * 11;	// 352
		tablec[i + 13] = T / 16 * 7;	// 224
		tablec[i + 14] = T / 16 * 15;	// 480
		tablec[i + 15] = T / 32;		// 16
	}
}

int main()
{
	bool hasAes;
	bool hasAvs;
	bool hasAvx2;
	bool isx86emu;
	bool is64;

	ConsoleUtils::SizeConsole();
	PrintTitle();

#if !defined(_OPENMP)
	PrintHeader("Warning! This library requires OpenMP support, the test can not coninue!");
	PrintHeader("An error has occurred! Press any key to close..", "");
	GetResponse();

	return 0;
#endif

	std::string data("");
	try
	{
		TestUtils::Read(TestFiles::AESAVS::AESAVSKEY128, data);
	}
	catch (std::exception&) 
	{
		data = "";
	}

	if (data.size() == 0)
	{
		PrintHeader("Warning! Could not find the cipher test vector KAT files!");
		PrintHeader("The Win/Test/Vectors folder must be in the executables path.", "");
		PrintHeader("An error has occurred! Press any key to close..", "");
		GetResponse();

		return 0;
	}

	hasAes = false;
	hasAvs = false;
	hasAvx2 = false;
	isx86emu = false;
	is64 = false;

	try
	{
		Common::CpuDetect detect;

		hasAes = detect.AESNI();
		hasAvs = detect.AVX();
		hasAvx2 = detect.AVX2();
		isx86emu = detect.IsX86Emulation();
		is64 = detect.IsX64();
	}
	catch (std::exception&)
	{
		PrintHeader("An error has occurred! This platform does not support cpudetect!", "");
		GetResponse();

		return 0;
	}

#if ((!defined(_M_X64)) && (!defined(__x86_64__))) && ((defined(__AVX__) || defined(__AVX2__)) && (!defined(_DEBUG)))
	if (is64 || isx86emu)
	{
		PrintHeader("Warning! Compiling x86/Release on a 64bit system using AVX/AVX2 will cause memory alignment errors.", "");
		PrintHeader("To test x86/Release, compile on a true x86 system, or disable enhanced instruction sets (arch:IA32), or run in x86/Debug mode.", "");
		PrintHeader("Tests aborted! Press any key to close..", "");
		GetResponse();

		return 0;
	}
#endif

	if (hasAes)
	{
		PrintHeader("AES-NI intrinsics support has been detected on this system.");
	}
	else
	{
		PrintHeader("AES-NI intrinsics support was not detected on this system.");
	}
	PrintHeader("", "");

	if (hasAvx2)
	{
#if !defined(__AVX2__)
		PrintHeader("Warning! AVX2 support was detected! Set the enhanced instruction set to arch:AVX2 for best performance.");
#else
		PrintHeader("AVX2 intrinsics support has been enabled.");
#endif
	}
	else if (hasAvs)
	{
#if defined(__AVX2__)
		PrintHeader("AVX2 is not supported on this system! AVX intrinsics support is available, set enable enhanced instruction set to arch:AVX");
#elif !defined(__AVX__)
		PrintHeader("AVX intrinsics support has been detected, set enhanced instruction set to arch:AVX for best performance.");
#else
		PrintHeader("AVX intrinsics support has been enabled.");
#endif
	}
	else
	{
		PrintHeader("The minimum SIMD intrinsics support (AVX) was not detected, intrinsics have been disabled!");
	}
	PrintHeader("", "");

	try
	{
#if defined (_DEBUG)
		PrintHeader("Warning! Compile as Release with correct platform (x86/x64) for accurate timings");
		PrintHeader("", "");
#endif

		if (CanTest("Press 'Y' then Enter to run Diagnostic Tests, any other key to cancel: "))
		{
			PrintHeader("TESTING SYMMETRIC BLOCK CIPHERS");

			if (hasAes)
			{
				PrintHeader("Testing the AES-NI implementation (AHX)");
				RunTest(new AesAvsTest(true));
			}
			PrintHeader("Testing the AES software implementation (RHX)");
			RunTest(new AesAvsTest());
			if (hasAes)
			{
				PrintHeader("Testing the AES-NI implementation (AHX)");
				RunTest(new AesFipsTest(true));
			}

			PrintHeader("Testing the AES software implementation (RHX)");
			RunTest(new AesFipsTest());
			RunTest(new RijndaelTest());
			RunTest(new SerpentTest());
			RunTest(new TwofishTest());
			PrintHeader("TESTING HX EXTENDED CIPHERS");
			RunTest(new HXCipherTest());
			PrintHeader("TESTING SYMMETRIC CIPHER MODES");
			RunTest(new CipherModeTest());
			PrintHeader("TESTING SYMMETRIC CIPHER AEAD MODES");
			RunTest(new AEADTest());
			PrintHeader("TESTING PARALLEL CIPHER MODES");
			RunTest(new ParallelModeTest());
			PrintHeader("TESTING CIPHER PADDING MODES");
			RunTest(new PaddingTest());
			PrintHeader("TESTING SYMMETRIC STREAM CIPHERS");
			RunTest(new ChaChaTest());
			RunTest(new SalsaTest());
			PrintHeader("TESTING CRYPTOGRAPHIC STREAM PROCESSORS");
			RunTest(new CipherStreamTest());
			RunTest(new DigestStreamTest());
			RunTest(new MacStreamTest());
			PrintHeader("TESTING CRYPTOGRAPHIC HASH GENERATORS");
			RunTest(new Blake2Test());
			RunTest(new KeccakTest());
			RunTest(new SHA2Test());
			RunTest(new SkeinTest());
			PrintHeader("TESTING MESSAGE AUTHENTICATION CODE GENERATORS");
			RunTest(new CMACTest());
			RunTest(new GMACTest());
			RunTest(new HMACTest());
			RunTest(new KMACTest());
			RunTest(new Poly1305Test());
			PrintHeader("TESTING PSEUDO RANDOM NUMBER GENERATORS");
			RunTest(new PrngTest());
			PrintHeader("TESTING KEY DERIVATION FUNCTIONS");
			RunTest(new HKDFTest());
			RunTest(new KDF2Test());
			RunTest(new PBKDF2Test());
			RunTest(new SCRYPTTest());
			RunTest(new SHAKETest());
			PrintHeader("TESTING DETERMINISTIC RANDOM BYTE GENERATORS");
			RunTest(new BCGTest());
			RunTest(new CSGTest());
			RunTest(new HMGTest());
			PrintHeader("TESTING KEY GENERATOR AND SECURE KEYS");
			RunTest(new SymmetricKeyGeneratorTest());
			RunTest(new SecureStreamTest());
			RunTest(new SymmetricKeyTest());
			PrintHeader("TESTING VECTORIZED MEMORY FUNCTIONS");
			RunTest(new MemUtilsTest());
			RunTest(new SimdWrapperTest());
			PrintHeader("TESTING UTILITY CLASS FUNCTIONS");
			RunTest(new UtilityTest());
			PrintHeader("TESTING ASYMMETRIC CIPHERS");
			RunTest(new McElieceTest());
			RunTest(new ModuleLWETest());
			RunTest(new NTRUTest());
			RunTest(new RingLWETest());
		}
		else
		{
			ConsoleUtils::WriteLine("Diagnostic tests were Cancelled..");
		}

		ConsoleUtils::WriteLine("");
		ConsoleUtils::WriteLine("");

#if defined(__AVX__)
		if (CanTest("Press 'Y' then Enter to run SIMD Memory operations Speed Tests, any other key to cancel: "))
		{
			RunTest(new SimdSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("SIMD Memory Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");
#endif

		if (CanTest("Press 'Y' then Enter to run Symmetric Cipher Speed Tests, any other key to cancel: "))
		{
			RunTest(new CipherSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Cipher Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");

		if (CanTest("Press 'Y' then Enter to run Message Digest Speed Tests, any other key to cancel: "))
		{
			RunTest(new DigestSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Digest Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");

		if (CanTest("Press 'Y' then Enter to run Asymmetric Cipher Speed Tests, any other key to cancel: "))
		{
			RunTest(new AsymmetricSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Asymmetric Cipher Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");

		PrintHeader("Completed! Press any key to close..", "");
		GetResponse();

		return 0;
	}
	catch (std::exception&)
	{
		PrintHeader("An error has occurred! Press any key to close..", "");
		GetResponse();

		return 0;
	}
}
