#include "DLTMPolyMath.h"
#include "Keccak.h"
#include "MemoryTools.h"

NAMESPACE_DILITHIUM

using Digest::Keccak;
using Tools::MemoryTools;

const uint32_t DLTMPolyMath::Zetas[DILITHIUM_N] =
{
	0x00000000L, 0x000064F7L, 0xFFD83102L, 0xFFF81503L, 0x00039E44L, 0xFFF42118L, 0xFFF2A128L, 0x00071E24L,
	0x001BDE2BL, 0x0023E92BL, 0xFFFA84ADL, 0xFFE0147FL, 0x002F9A75L, 0xFFD3FB09L, 0x002F7A49L, 0x0028E527L,
	0x00299658L, 0x000FA070L, 0xFFEF85A4L, 0x0036B788L, 0xFFF79D90L, 0xFFEEEAA0L, 0x0027F968L, 0xFFDFD37BL,
	0xFFDFADD6L, 0xFFC51AE7L, 0xFFEAA4F7L, 0xFFCDFC98L, 0x001AD035L, 0xFFFFB422L, 0x003D3201L, 0x000445C5L,
	0x00294A67L, 0x00017620L, 0x002EF4CDL, 0x0035DEC5L, 0xFFE6A503L, 0xFFC9302CL, 0xFFD947D4L, 0x003BBEAFL,
	0xFFC51585L, 0xFFD18E7CL, 0x00368A96L, 0xFFD43E41L, 0x00360400L, 0xFFFB6A4DL, 0x0023D69CL, 0xFFF7C55DL,
	0xFFE6123DL, 0xFFE6EAD6L, 0x00357E1EL, 0xFFC5AF59L, 0x0035843FL, 0xFFDF5617L, 0xFFE7945CL, 0x0038738CL,
	0x000C63A8L, 0x00081B9AL, 0x000E8F76L, 0x003B3853L, 0x003B8534L, 0xFFD8FC30L, 0x001F9D54L, 0xFFD54F2DL,
	0xFFC406E5L, 0xFFE8AC81L, 0xFFC7E1CFL, 0xFFD19819L, 0xFFE9D65DL, 0x003509EEL, 0x002135C7L, 0xFFE7CFBBL,
	0xFFECCF75L, 0x001D9772L, 0xFFC1B072L, 0xFFF0BCF6L, 0xFFCF5280L, 0xFFCFD2AEL, 0xFFC890E0L, 0x0001EFCAL,
	0x003410F2L, 0xFFF0FE85L, 0x0020C638L, 0x00296E9FL, 0xFFD2B7A3L, 0xFFC7A44BL, 0xFFF9BA6DL, 0xFFDA3409L,
	0xFFF5C282L, 0xFFED4113L, 0xFFFFA63BL, 0xFFEC09F7L, 0xFFFA2BDDL, 0x001495D4L, 0x001C4563L, 0xFFEA2C62L,
	0xFFCCFBE9L, 0x00040AF0L, 0x0007C417L, 0x002F4588L, 0x0000AD00L, 0xFFEF36BEL, 0x000DCD44L, 0x003C675AL,
	0xFFC72BCAL, 0xFFFFDE7EL, 0x00193948L, 0xFFCE69C0L, 0x0024756CL, 0xFFFCC7DFL, 0x000B98A1L, 0xFFEBE808L,
	0x0002E46CL, 0xFFC9C808L, 0x003036C2L, 0xFFE3BFF6L, 0xFFDB3C93L, 0xFFFD4AE0L, 0x00141305L, 0x00147792L,
	0x00139E25L, 0xFFE7D0E0L, 0xFFF39944L, 0xFFEA0802L, 0xFFD1EEA2L, 0xFFC4C79CL, 0xFFC8A057L, 0x003A97D9L,
	0x001FEA93L, 0x0033FF5AL, 0x002358D4L, 0x003A41F8L, 0xFFCCFF72L, 0x00223DFBL, 0xFFDAAB9FL, 0xFFC9A422L,
	0x000412F5L, 0x00252587L, 0xFFED24F0L, 0x00359B5DL, 0xFFCA48A0L, 0xFFC6A2FCL, 0xFFEDBB56L, 0xFFCF45DEL,
	0x000DBE5EL, 0x001C5E1AL, 0x000DE0E6L, 0x000C7F5AL, 0x00078F83L, 0xFFE7628AL, 0xFFFF5704L, 0xFFF806FCL,
	0xFFF60021L, 0xFFD05AF6L, 0x001F0084L, 0x0030EF86L, 0xFFC9B97DL, 0xFFF7FCD6L, 0xFFF44592L, 0xFFC921C2L,
	0x00053919L, 0x0004610CL, 0xFFDACD41L, 0x003EB01BL, 0x003472E7L, 0xFFCD003BL, 0x001A7CC7L, 0x00031924L,
	0x002B5EE5L, 0x00291199L, 0xFFD87A3AL, 0x00134D71L, 0x003DE11CL, 0x00130984L, 0x0025F051L, 0x00185A46L,
	0xFFC68518L, 0x001314BEL, 0x00283891L, 0xFFC9DB90L, 0xFFD25089L, 0x001C853FL, 0x001D0B4BL, 0xFFEFF6A6L,
	0xFFEBA8BEL, 0x0012E11BL, 0xFFCD5E3EL, 0xFFEA2D2FL, 0xFFF91DE4L, 0x001406C7L, 0x00327283L, 0xFFE20D6EL,
	0xFFEC7953L, 0x001D4099L, 0xFFD92578L, 0xFFEB05ADL, 0x0016E405L, 0x000BDBE7L, 0x00221DE8L, 0x0033F8CFL,
	0xFFF7B934L, 0xFFD4CA0CL, 0xFFE67FF8L, 0xFFE3D157L, 0xFFD8911BL, 0xFFC72C12L, 0x000910D8L, 0xFFC65E1FL,
	0xFFE14658L, 0x00251D8BL, 0x002573B7L, 0xFFFD7C8FL, 0x001DDD98L, 0x00336898L, 0x0002D4BBL, 0xFFED93A7L,
	0xFFCF6CBEL, 0x00027C1CL, 0x0018AA08L, 0x002DFD71L, 0x000C5CA5L, 0x0019379AL, 0xFFC7A167L, 0xFFE48C3DL,
	0xFFD1A13CL, 0x0035C539L, 0x003B0115L, 0x00041DC0L, 0x0021C4F7L, 0xFFF11BF4L, 0x001A35E7L, 0x0007340EL,
	0xFFF97D45L, 0x001A4CD0L, 0xFFE47CAEL, 0x001D2668L, 0xFFE68E98L, 0xFFEF2633L, 0xFFFC05DAL, 0xFFC57FDBL,
	0xFFD32764L, 0xFFDDE1AFL, 0xFFF993DDL, 0xFFDD1D09L, 0x0002CC93L, 0xFFF11805L, 0x00189C2AL, 0xFFC9E5A9L,
	0xFFF78A50L, 0x003BCF2CL, 0xFFFF434EL, 0xFFEB36DFL, 0x003C15CAL, 0x00155E68L, 0xFFF316B6L, 0x001E29CEL
};

#if defined(CEX_HAS_AVX2)

CEX_ALIGN(64) static const uint8_t RejAvx2[256][8] = 
{
	{ 0,  0,  0,  0,  0,  0,  0,  0}, { 0,  0,  0,  0,  0,  0,  0,  0}, { 1,  0,  0,  0,  0,  0,  0,  0}, { 0,  1,  0,  0,  0,  0,  0,  0},
	{ 2,  0,  0,  0,  0,  0,  0,  0}, { 0,  2,  0,  0,  0,  0,  0,  0}, { 1,  2,  0,  0,  0,  0,  0,  0}, { 0,  1,  2,  0,  0,  0,  0,  0},
	{ 3,  0,  0,  0,  0,  0,  0,  0}, { 0,  3,  0,  0,  0,  0,  0,  0}, { 1,  3,  0,  0,  0,  0,  0,  0}, { 0,  1,  3,  0,  0,  0,  0,  0},
	{ 2,  3,  0,  0,  0,  0,  0,  0}, { 0,  2,  3,  0,  0,  0,  0,  0}, { 1,  2,  3,  0,  0,  0,  0,  0}, { 0,  1,  2,  3,  0,  0,  0,  0},
	{ 4,  0,  0,  0,  0,  0,  0,  0}, { 0,  4,  0,  0,  0,  0,  0,  0}, { 1,  4,  0,  0,  0,  0,  0,  0}, { 0,  1,  4,  0,  0,  0,  0,  0},
	{ 2,  4,  0,  0,  0,  0,  0,  0}, { 0,  2,  4,  0,  0,  0,  0,  0}, { 1,  2,  4,  0,  0,  0,  0,  0}, { 0,  1,  2,  4,  0,  0,  0,  0},
	{ 3,  4,  0,  0,  0,  0,  0,  0}, { 0,  3,  4,  0,  0,  0,  0,  0}, { 1,  3,  4,  0,  0,  0,  0,  0}, { 0,  1,  3,  4,  0,  0,  0,  0},
	{ 2,  3,  4,  0,  0,  0,  0,  0}, { 0,  2,  3,  4,  0,  0,  0,  0}, { 1,  2,  3,  4,  0,  0,  0,  0}, { 0,  1,  2,  3,  4,  0,  0,  0},
	{ 5,  0,  0,  0,  0,  0,  0,  0}, { 0,  5,  0,  0,  0,  0,  0,  0}, { 1,  5,  0,  0,  0,  0,  0,  0}, { 0,  1,  5,  0,  0,  0,  0,  0},
	{ 2,  5,  0,  0,  0,  0,  0,  0}, { 0,  2,  5,  0,  0,  0,  0,  0}, { 1,  2,  5,  0,  0,  0,  0,  0}, { 0,  1,  2,  5,  0,  0,  0,  0},
	{ 3,  5,  0,  0,  0,  0,  0,  0}, { 0,  3,  5,  0,  0,  0,  0,  0}, { 1,  3,  5,  0,  0,  0,  0,  0}, { 0,  1,  3,  5,  0,  0,  0,  0},
	{ 2,  3,  5,  0,  0,  0,  0,  0}, { 0,  2,  3,  5,  0,  0,  0,  0}, { 1,  2,  3,  5,  0,  0,  0,  0}, { 0,  1,  2,  3,  5,  0,  0,  0},
	{ 4,  5,  0,  0,  0,  0,  0,  0}, { 0,  4,  5,  0,  0,  0,  0,  0}, { 1,  4,  5,  0,  0,  0,  0,  0}, { 0,  1,  4,  5,  0,  0,  0,  0},
	{ 2,  4,  5,  0,  0,  0,  0,  0}, { 0,  2,  4,  5,  0,  0,  0,  0}, { 1,  2,  4,  5,  0,  0,  0,  0}, { 0,  1,  2,  4,  5,  0,  0,  0},
	{ 3,  4,  5,  0,  0,  0,  0,  0}, { 0,  3,  4,  5,  0,  0,  0,  0}, { 1,  3,  4,  5,  0,  0,  0,  0}, { 0,  1,  3,  4,  5,  0,  0,  0},
	{ 2,  3,  4,  5,  0,  0,  0,  0}, { 0,  2,  3,  4,  5,  0,  0,  0}, { 1,  2,  3,  4,  5,  0,  0,  0}, { 0,  1,  2,  3,  4,  5,  0,  0},
	{ 6,  0,  0,  0,  0,  0,  0,  0}, { 0,  6,  0,  0,  0,  0,  0,  0}, { 1,  6,  0,  0,  0,  0,  0,  0}, { 0,  1,  6,  0,  0,  0,  0,  0},
	{ 2,  6,  0,  0,  0,  0,  0,  0}, { 0,  2,  6,  0,  0,  0,  0,  0}, { 1,  2,  6,  0,  0,  0,  0,  0}, { 0,  1,  2,  6,  0,  0,  0,  0},
	{ 3,  6,  0,  0,  0,  0,  0,  0}, { 0,  3,  6,  0,  0,  0,  0,  0}, { 1,  3,  6,  0,  0,  0,  0,  0}, { 0,  1,  3,  6,  0,  0,  0,  0},
	{ 2,  3,  6,  0,  0,  0,  0,  0}, { 0,  2,  3,  6,  0,  0,  0,  0}, { 1,  2,  3,  6,  0,  0,  0,  0}, { 0,  1,  2,  3,  6,  0,  0,  0},
	{ 4,  6,  0,  0,  0,  0,  0,  0}, { 0,  4,  6,  0,  0,  0,  0,  0}, { 1,  4,  6,  0,  0,  0,  0,  0}, { 0,  1,  4,  6,  0,  0,  0,  0},
	{ 2,  4,  6,  0,  0,  0,  0,  0}, { 0,  2,  4,  6,  0,  0,  0,  0}, { 1,  2,  4,  6,  0,  0,  0,  0}, { 0,  1,  2,  4,  6,  0,  0,  0},
	{ 3,  4,  6,  0,  0,  0,  0,  0}, { 0,  3,  4,  6,  0,  0,  0,  0}, { 1,  3,  4,  6,  0,  0,  0,  0}, { 0,  1,  3,  4,  6,  0,  0,  0},
	{ 2,  3,  4,  6,  0,  0,  0,  0}, { 0,  2,  3,  4,  6,  0,  0,  0}, { 1,  2,  3,  4,  6,  0,  0,  0}, { 0,  1,  2,  3,  4,  6,  0,  0},
	{ 5,  6,  0,  0,  0,  0,  0,  0}, { 0,  5,  6,  0,  0,  0,  0,  0}, { 1,  5,  6,  0,  0,  0,  0,  0}, { 0,  1,  5,  6,  0,  0,  0,  0},
	{ 2,  5,  6,  0,  0,  0,  0,  0}, { 0,  2,  5,  6,  0,  0,  0,  0}, { 1,  2,  5,  6,  0,  0,  0,  0}, { 0,  1,  2,  5,  6,  0,  0,  0},
	{ 3,  5,  6,  0,  0,  0,  0,  0}, { 0,  3,  5,  6,  0,  0,  0,  0}, { 1,  3,  5,  6,  0,  0,  0,  0}, { 0,  1,  3,  5,  6,  0,  0,  0},
	{ 2,  3,  5,  6,  0,  0,  0,  0}, { 0,  2,  3,  5,  6,  0,  0,  0}, { 1,  2,  3,  5,  6,  0,  0,  0}, { 0,  1,  2,  3,  5,  6,  0,  0},
	{ 4,  5,  6,  0,  0,  0,  0,  0}, { 0,  4,  5,  6,  0,  0,  0,  0}, { 1,  4,  5,  6,  0,  0,  0,  0}, { 0,  1,  4,  5,  6,  0,  0,  0},
	{ 2,  4,  5,  6,  0,  0,  0,  0}, { 0,  2,  4,  5,  6,  0,  0,  0}, { 1,  2,  4,  5,  6,  0,  0,  0}, { 0,  1,  2,  4,  5,  6,  0,  0},
	{ 3,  4,  5,  6,  0,  0,  0,  0}, { 0,  3,  4,  5,  6,  0,  0,  0}, { 1,  3,  4,  5,  6,  0,  0,  0}, { 0,  1,  3,  4,  5,  6,  0,  0},
	{ 2,  3,  4,  5,  6,  0,  0,  0}, { 0,  2,  3,  4,  5,  6,  0,  0}, { 1,  2,  3,  4,  5,  6,  0,  0}, { 0,  1,  2,  3,  4,  5,  6,  0},
	{ 7,  0,  0,  0,  0,  0,  0,  0}, { 0,  7,  0,  0,  0,  0,  0,  0}, { 1,  7,  0,  0,  0,  0,  0,  0}, { 0,  1,  7,  0,  0,  0,  0,  0},
	{ 2,  7,  0,  0,  0,  0,  0,  0}, { 0,  2,  7,  0,  0,  0,  0,  0}, { 1,  2,  7,  0,  0,  0,  0,  0}, { 0,  1,  2,  7,  0,  0,  0,  0},
	{ 3,  7,  0,  0,  0,  0,  0,  0}, { 0,  3,  7,  0,  0,  0,  0,  0}, { 1,  3,  7,  0,  0,  0,  0,  0}, { 0,  1,  3,  7,  0,  0,  0,  0},
	{ 2,  3,  7,  0,  0,  0,  0,  0}, { 0,  2,  3,  7,  0,  0,  0,  0}, { 1,  2,  3,  7,  0,  0,  0,  0}, { 0,  1,  2,  3,  7,  0,  0,  0},
	{ 4,  7,  0,  0,  0,  0,  0,  0}, { 0,  4,  7,  0,  0,  0,  0,  0}, { 1,  4,  7,  0,  0,  0,  0,  0}, { 0,  1,  4,  7,  0,  0,  0,  0},
	{ 2,  4,  7,  0,  0,  0,  0,  0}, { 0,  2,  4,  7,  0,  0,  0,  0}, { 1,  2,  4,  7,  0,  0,  0,  0}, { 0,  1,  2,  4,  7,  0,  0,  0},
	{ 3,  4,  7,  0,  0,  0,  0,  0}, { 0,  3,  4,  7,  0,  0,  0,  0}, { 1,  3,  4,  7,  0,  0,  0,  0}, { 0,  1,  3,  4,  7,  0,  0,  0},
	{ 2,  3,  4,  7,  0,  0,  0,  0}, { 0,  2,  3,  4,  7,  0,  0,  0}, { 1,  2,  3,  4,  7,  0,  0,  0}, { 0,  1,  2,  3,  4,  7,  0,  0},
	{ 5,  7,  0,  0,  0,  0,  0,  0}, { 0,  5,  7,  0,  0,  0,  0,  0}, { 1,  5,  7,  0,  0,  0,  0,  0}, { 0,  1,  5,  7,  0,  0,  0,  0},
	{ 2,  5,  7,  0,  0,  0,  0,  0}, { 0,  2,  5,  7,  0,  0,  0,  0}, { 1,  2,  5,  7,  0,  0,  0,  0}, { 0,  1,  2,  5,  7,  0,  0,  0},
	{ 3,  5,  7,  0,  0,  0,  0,  0}, { 0,  3,  5,  7,  0,  0,  0,  0}, { 1,  3,  5,  7,  0,  0,  0,  0}, { 0,  1,  3,  5,  7,  0,  0,  0},
	{ 2,  3,  5,  7,  0,  0,  0,  0}, { 0,  2,  3,  5,  7,  0,  0,  0}, { 1,  2,  3,  5,  7,  0,  0,  0}, { 0,  1,  2,  3,  5,  7,  0,  0},
	{ 4,  5,  7,  0,  0,  0,  0,  0}, { 0,  4,  5,  7,  0,  0,  0,  0}, { 1,  4,  5,  7,  0,  0,  0,  0}, { 0,  1,  4,  5,  7,  0,  0,  0},
	{ 2,  4,  5,  7,  0,  0,  0,  0}, { 0,  2,  4,  5,  7,  0,  0,  0}, { 1,  2,  4,  5,  7,  0,  0,  0}, { 0,  1,  2,  4,  5,  7,  0,  0},
	{ 3,  4,  5,  7,  0,  0,  0,  0}, { 0,  3,  4,  5,  7,  0,  0,  0}, { 1,  3,  4,  5,  7,  0,  0,  0}, { 0,  1,  3,  4,  5,  7,  0,  0},
	{ 2,  3,  4,  5,  7,  0,  0,  0}, { 0,  2,  3,  4,  5,  7,  0,  0}, { 1,  2,  3,  4,  5,  7,  0,  0}, { 0,  1,  2,  3,  4,  5,  7,  0},
	{ 6,  7,  0,  0,  0,  0,  0,  0}, { 0,  6,  7,  0,  0,  0,  0,  0}, { 1,  6,  7,  0,  0,  0,  0,  0}, { 0,  1,  6,  7,  0,  0,  0,  0},
	{ 2,  6,  7,  0,  0,  0,  0,  0}, { 0,  2,  6,  7,  0,  0,  0,  0}, { 1,  2,  6,  7,  0,  0,  0,  0}, { 0,  1,  2,  6,  7,  0,  0,  0},
	{ 3,  6,  7,  0,  0,  0,  0,  0}, { 0,  3,  6,  7,  0,  0,  0,  0}, { 1,  3,  6,  7,  0,  0,  0,  0}, { 0,  1,  3,  6,  7,  0,  0,  0},
	{ 2,  3,  6,  7,  0,  0,  0,  0}, { 0,  2,  3,  6,  7,  0,  0,  0}, { 1,  2,  3,  6,  7,  0,  0,  0}, { 0,  1,  2,  3,  6,  7,  0,  0},
	{ 4,  6,  7,  0,  0,  0,  0,  0}, { 0,  4,  6,  7,  0,  0,  0,  0}, { 1,  4,  6,  7,  0,  0,  0,  0}, { 0,  1,  4,  6,  7,  0,  0,  0},
	{ 2,  4,  6,  7,  0,  0,  0,  0}, { 0,  2,  4,  6,  7,  0,  0,  0}, { 1,  2,  4,  6,  7,  0,  0,  0}, { 0,  1,  2,  4,  6,  7,  0,  0},
	{ 3,  4,  6,  7,  0,  0,  0,  0}, { 0,  3,  4,  6,  7,  0,  0,  0}, { 1,  3,  4,  6,  7,  0,  0,  0}, { 0,  1,  3,  4,  6,  7,  0,  0},
	{ 2,  3,  4,  6,  7,  0,  0,  0}, { 0,  2,  3,  4,  6,  7,  0,  0}, { 1,  2,  3,  4,  6,  7,  0,  0}, { 0,  1,  2,  3,  4,  6,  7,  0},
	{ 5,  6,  7,  0,  0,  0,  0,  0}, { 0,  5,  6,  7,  0,  0,  0,  0}, { 1,  5,  6,  7,  0,  0,  0,  0}, { 0,  1,  5,  6,  7,  0,  0,  0},
	{ 2,  5,  6,  7,  0,  0,  0,  0}, { 0,  2,  5,  6,  7,  0,  0,  0}, { 1,  2,  5,  6,  7,  0,  0,  0}, { 0,  1,  2,  5,  6,  7,  0,  0},
	{ 3,  5,  6,  7,  0,  0,  0,  0}, { 0,  3,  5,  6,  7,  0,  0,  0}, { 1,  3,  5,  6,  7,  0,  0,  0}, { 0,  1,  3,  5,  6,  7,  0,  0},
	{ 2,  3,  5,  6,  7,  0,  0,  0}, { 0,  2,  3,  5,  6,  7,  0,  0}, { 1,  2,  3,  5,  6,  7,  0,  0}, { 0,  1,  2,  3,  5,  6,  7,  0},
	{ 4,  5,  6,  7,  0,  0,  0,  0}, { 0,  4,  5,  6,  7,  0,  0,  0}, { 1,  4,  5,  6,  7,  0,  0,  0}, { 0,  1,  4,  5,  6,  7,  0,  0},
	{ 2,  4,  5,  6,  7,  0,  0,  0}, { 0,  2,  4,  5,  6,  7,  0,  0}, { 1,  2,  4,  5,  6,  7,  0,  0}, { 0,  1,  2,  4,  5,  6,  7,  0},
	{ 3,  4,  5,  6,  7,  0,  0,  0}, { 0,  3,  4,  5,  6,  7,  0,  0}, { 1,  3,  4,  5,  6,  7,  0,  0}, { 0,  1,  3,  4,  5,  6,  7,  0},
	{ 2,  3,  4,  5,  6,  7,  0,  0}, { 0,  2,  3,  4,  5,  6,  7,  0}, { 1,  2,  3,  4,  5,  6,  7,  0}, { 0,  1,  2,  3,  4,  5,  6,  7}
};

const int32_t DLTMPolyMath::Avx2Q[8] = { DILITHIUM_Q, DILITHIUM_Q, DILITHIUM_Q, DILITHIUM_Q,
    DILITHIUM_Q, DILITHIUM_Q, DILITHIUM_Q, DILITHIUM_Q };
const int32_t DLTMPolyMath::Avx2QINV[8] = { DILITHIUM_QINV, DILITHIUM_QINV, DILITHIUM_QINV, DILITHIUM_QINV,
    DILITHIUM_QINV, DILITHIUM_QINV, DILITHIUM_QINV, DILITHIUM_Q };

#define _mm256_blendv_epi32(a,b,mask) \
  _mm256_castps_si256(_mm256_blendv_ps(_mm256_castsi256_ps(a), \
                                       _mm256_castsi256_ps(b), \
                                       _mm256_castsi256_ps(mask)))

void DLTMPolyMath::PolyAdd(std::array<int32_t, 256> &C, const std::array<int32_t, 256> &A, const std::array<int32_t, 256> &B)
{
    __m256i vec0;
    __m256i vec1;

    for (size_t i = 0; i < DILITHIUM_N; i += 8)
    {
        vec0 = _mm256_load_si256((__m256i*)&A[i]);
        vec1 = _mm256_load_si256((__m256i*)&B[i]);
        vec0 = _mm256_add_epi32(vec0, vec1);
        _mm256_store_si256((__m256i*)&C[i], vec0);
    }
}

void DLTMPolyMath::PolyCaddQ(std::array<int32_t, 256> &A)
{
    const __m256i q = _mm256_load_si256((__m256i*)&Avx2Q[0]);
    const __m256i zero = _mm256_setzero_si256();
    __m256i f;
    __m256i g;

    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        f = _mm256_load_si256((__m256i*)&A[8 * i]);
        g = _mm256_blendv_epi32(zero, q, f);
        f = _mm256_add_epi32(f, g);
        _mm256_store_si256((__m256i*)&A[8 * i], f);
    }
}

int32_t DLTMPolyMath::PolyChkNorm(const std::array<int32_t, 256> &A, uint32_t B)
{
    const __m256i bound = _mm256_set1_epi32(B - 1);
    __m256i f;
    __m256i t;
    int32_t r;

    if (B > (DILITHIUM_Q - 1) / 8)
    {
        r = 1;
    }
    else
    {
        t = _mm256_setzero_si256();

        for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
        {
            f = _mm256_load_si256((__m256i*)&A[8 * i]);
            f = _mm256_abs_epi32(f);
            f = _mm256_cmpgt_epi32(f, bound);
            t = _mm256_or_si256(t, f);
        }

        r = _mm256_testz_si256(t, t) == 0 ? 1 : 0;
    }

    return r;
}

void DLTMPolyMath::PolyDecompose(std::array<int32_t, 256> &A1, std::array<int32_t, 256> &A0, const std::array<int32_t, 256> &A, uint32_t Gamma2)
{
	if (Gamma2 == (DILITHIUM_Q - 1) / 32)
	{
		const __m256i q = _mm256_load_si256((__m256i*)&Avx2Q[0]);
		const __m256i hq = _mm256_srli_epi32(q, 1);
		const __m256i v = _mm256_set1_epi32(1025);
		const __m256i alpha = _mm256_set1_epi32(2 * Gamma2);
		const __m256i off = _mm256_set1_epi32(127);
		const __m256i shift = _mm256_set1_epi32(512);
		const __m256i mask = _mm256_set1_epi32(15);
		__m256i f;
		__m256i f0;
		__m256i f1;

		for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
		{
			f = _mm256_load_si256((__m256i*)&A[8 * i]);
			f1 = _mm256_add_epi32(f, off);
			f1 = _mm256_srli_epi32(f1, 7);
			f1 = _mm256_mulhi_epu16(f1, v);
			f1 = _mm256_mulhrs_epi16(f1, shift);
			f1 = _mm256_and_si256(f1, mask);
			f0 = _mm256_mullo_epi32(f1, alpha);
			f0 = _mm256_sub_epi32(f, f0);
			f = _mm256_cmpgt_epi32(f0, hq);
			f = _mm256_and_si256(f, q);
			f0 = _mm256_sub_epi32(f0, f);
			_mm256_store_si256((__m256i*)&A1[8 * i], f1);
			_mm256_store_si256((__m256i*)&A0[8 * i], f0);
		}
	}
	else if (Gamma2 == (DILITHIUM_Q - 1) / 88)
	{
		const __m256i q = _mm256_load_si256((__m256i*)&Avx2Q[0]);
		const __m256i hq = _mm256_srli_epi32(q, 1);
		const __m256i v = _mm256_set1_epi32(11275);
		const __m256i alpha = _mm256_set1_epi32(2 * Gamma2);
		const __m256i off = _mm256_set1_epi32(127);
		const __m256i shift = _mm256_set1_epi32(128);
		const __m256i max = _mm256_set1_epi32(43);
		const __m256i zero = _mm256_setzero_si256();
		__m256i f;
		__m256i f0;
		__m256i f1;
		__m256i t;

		for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
		{
			f = _mm256_load_si256((__m256i*)&A[8 * i]);
			f1 = _mm256_add_epi32(f, off);
			f1 = _mm256_srli_epi32(f1, 7);
			f1 = _mm256_mulhi_epu16(f1, v);
			f1 = _mm256_mulhrs_epi16(f1, shift);
			t = _mm256_cmpgt_epi32(f1, max);
			f1 = _mm256_blendv_epi8(f1, zero, t);
			f0 = _mm256_mullo_epi32(f1, alpha);
			f0 = _mm256_sub_epi32(f, f0);
			f = _mm256_cmpgt_epi32(f0, hq);
			f = _mm256_and_si256(f, q);
			f0 = _mm256_sub_epi32(f0, f);
			_mm256_store_si256((__m256i*)&A1[8 * i], f1);
			_mm256_store_si256((__m256i*)&A0[8 * i], f0);
		}
	}
}

uint32_t DLTMPolyMath::PolyMakeHint(std::array<int32_t, 256> &H, const std::array<int32_t, 256> &A0, const std::array<int32_t, 256> &A1, uint32_t Gamma2)
{
    const __m256i blo = _mm256_set1_epi32(Gamma2 + 1);
    const __m256i bhi = _mm256_set1_epi32(DILITHIUM_Q - Gamma2);
    const __m256i zero = _mm256_setzero_si256();
    const __m256i one = _mm256_set1_epi32(1);
    __m256i f0;
    __m256i f1;
    __m256i g0;
    __m256i g1;
    uint32_t r;

    r = 0;

    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        f0 = _mm256_load_si256((__m256i*)&A0[8 * i]);
        f1 = _mm256_load_si256((__m256i*)&A1[8 * i]);

        g0 = _mm256_cmpgt_epi32(blo, f0);
        g1 = _mm256_cmpgt_epi32(f0, bhi);
        g0 = _mm256_or_si256(g0, g1);
        g1 = _mm256_cmpeq_epi32(f0, bhi);
        f1 = _mm256_cmpeq_epi32(f1, zero);
        g1 = _mm256_and_si256(g1, f1);
        g0 = _mm256_or_si256(g0, g1);

        r += _mm_popcnt_u32(_mm256_movemask_ps(_mm256_castsi256_ps(g0)));
        g0 = _mm256_add_epi32(g0, one);
        _mm256_store_si256((__m256i*)&H[8 * i], g0);
    }

    return DILITHIUM_N - r;
}

void DLTMPolyMath::PolyPower2Round(std::array<int32_t, 256> &A1, std::array<int32_t, 256> &A0, const std::array<int32_t, 256> &A)
{
	__m256i f;
	__m256i f0;
	__m256i f1;
	const __m256i mask = _mm256_set1_epi32(-(int32_t)(1U << DILITHIUM_D));
	const __m256i half = _mm256_set1_epi32((1U << (DILITHIUM_D - 1)) - 1);

	for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
	{
		f = _mm256_load_si256((__m256i*)&A[8 * i]);
		f1 = _mm256_add_epi32(f, half);
		f0 = _mm256_and_si256(f1, mask);
		f1 = _mm256_srli_epi32(f1, DILITHIUM_D);
		f0 = _mm256_sub_epi32(f, f0);
		_mm256_store_si256((__m256i*)&A1[8 * i], f1);
		_mm256_store_si256((__m256i*)&A0[8 * i], f0);
	}
}

void DLTMPolyMath::PolyReduce(std::array<int32_t, 256> &A)
{
    const __m256i q = _mm256_load_si256((__m256i*)&Avx2Q[0]);
    const __m256i off = _mm256_set1_epi32(1 << 22);
    __m256i f;
    __m256i g;

    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        f = _mm256_load_si256((__m256i*)&A[8 * i]);
        g = _mm256_add_epi32(f, off);
        g = _mm256_srai_epi32(g, 23);
        g = _mm256_mullo_epi32(g, q);
        f = _mm256_sub_epi32(f, g);
        _mm256_store_si256((__m256i*)&A[8 * i], f);
    }
}

void DLTMPolyMath::PolyShiftL(std::array<int32_t, 256> &A)
{
    __m256i vec;

    for (size_t i = 0; i < DILITHIUM_N; i += 8)
    {
        vec = _mm256_load_si256((__m256i*)&A[i]);
        vec = _mm256_slli_epi32(vec, DILITHIUM_D);
        _mm256_store_si256((__m256i*)&A[i], vec);
    }
}

void DLTMPolyMath::PolySub(std::array<int32_t, 256> &C, const std::array<int32_t, 256> &A, const std::array<int32_t, 256> &B)
{
    __m256i vec0;
    __m256i vec1;

    for (size_t i = 0; i < DILITHIUM_N; i += 8)
    {
        vec0 = _mm256_load_si256((__m256i*)&A[i]);
        vec1 = _mm256_load_si256((__m256i*)&B[i]);
        vec0 = _mm256_sub_epi32(vec0, vec1);
        _mm256_store_si256((__m256i*)&C[i], vec0);
    }
}

void DLTMPolyMath::PolyUseHint(std::array<int32_t, 256> &B, const std::array<int32_t, 256> &A, const std::array<int32_t, 256> &H, uint32_t Gamma2)
{
    CEX_ALIGN(32) std::array<int32_t, DILITHIUM_N> a0;
    __m256i f;
    __m256i g;
    __m256i h;
    __m256i t;
    const __m256i zero = _mm256_setzero_si256();

	if (Gamma2 == (DILITHIUM_Q - 1) / 32)
	{
		const __m256i mask = _mm256_set1_epi32(15);
		PolyDecompose(B, a0, A, Gamma2);

		for (size_t i = 0; i < DILITHIUM_N / 8; i++)
		{
			f = _mm256_load_si256((__m256i*)&a0[8 * i]);
			g = _mm256_load_si256((__m256i*)&B[8 * i]);
			h = _mm256_load_si256((__m256i*)&H[8 * i]);
			t = _mm256_blendv_epi32(zero, h, f);
			t = _mm256_slli_epi32(t, 1);
			h = _mm256_sub_epi32(h, t);
			g = _mm256_add_epi32(g, h);
			g = _mm256_and_si256(g, mask);
			_mm256_store_si256((__m256i*) & B[8 * i], g);
		}
	}
	else if (Gamma2 == (DILITHIUM_Q - 1) / 88)
	{
		const __m256i max = _mm256_set1_epi32(43);
		PolyDecompose(B, a0, A, Gamma2);

		for (size_t i = 0; i < DILITHIUM_N / 8; i++)
		{
			f = _mm256_load_si256((__m256i*)&a0[8 * i]);
			g = _mm256_load_si256((__m256i*)&B[8 * i]);
			h = _mm256_load_si256((__m256i*)&H[8 * i]);
			t = _mm256_blendv_epi32(zero, h, f);
			t = _mm256_slli_epi32(t, 1);
			h = _mm256_sub_epi32(h, t);
			g = _mm256_add_epi32(g, h);
			g = _mm256_blendv_epi32(g, max, g);
			f = _mm256_cmpgt_epi32(g, max);
			g = _mm256_blendv_epi32(g, zero, f);
			_mm256_store_si256((__m256i*)&B[8 * i], g);
		}
	}
}

size_t DLTMPolyMath::RejUniformAvx2(std::array<int32_t, 256> &R, size_t ROffset, size_t RLength, const std::vector<uint8_t> &Buffer, size_t BufLength)
{
    const __m256i bound = _mm256_set1_epi32(DILITHIUM_Q);
    const __m256i mask = _mm256_set1_epi32(0x7FFFFF);
    const __m256i idx8 = _mm256_set_epi8(-1, 15, 14, 13, -1, 12, 11, 10, -1, 9, 8, 7, -1, 6, 5, 4,
        -1, 11, 10, 9, -1, 8, 7, 6, -1, 5, 4, 3, -1, 2, 1, 0);
    __m256i d;
    __m256i tmp;
    size_t pos;
    uint32_t ctr;
    uint32_t good;
    uint32_t t;

    ctr = 0;
    pos = 0;

    while (pos <= BufLength - 24)
    {
        d = _mm256_loadu_si256((__m256i*)&Buffer[pos]);
        d = _mm256_permute4x64_epi64(d, 0x94);
        d = _mm256_shuffle_epi8(d, idx8);
        d = _mm256_and_si256(d, mask);
        pos += 24;

        tmp = _mm256_sub_epi32(d, bound);
        good = _mm256_movemask_ps(_mm256_castsi256_ps(tmp));
        tmp = _mm256_cvtepu8_epi32(_mm_loadl_epi64((__m128i*)&RejAvx2[good]));
        d = _mm256_permutevar8x32_epi32(d, tmp);
        _mm256_storeu_si256((__m256i*)&R[ROffset + ctr], d);
        ctr += _mm_popcnt_u32(good);

        if (ctr > DILITHIUM_N - 8)
        {
            break;
        }
    }

    while (ctr < DILITHIUM_N && pos <= BufLength - 3)
    {
        t = Buffer[pos];
        ++pos;
        t |= (uint32_t)Buffer[pos] << 8;
        ++pos;
        t |= (uint32_t)Buffer[pos] << 16;
        ++pos;
        t &= 0x7FFFFF;

        if (t < DILITHIUM_Q)
        {
            R[ROffset + ctr] = t;
            ++ctr;
        }
    }

    return ctr;
}

void DLTMPolyMath::PolyUniform4x(std::array<int32_t, 256> &A0, std::array<int32_t, 256> &A1, std::array<int32_t, 256> &A2, std::array<int32_t, 256> &A3,
    const std::vector<uint8_t> &Seed, uint16_t Nonce0, uint16_t Nonce1, uint16_t Nonce2, uint16_t Nonce3)
{
    std::vector<__m256i> ksi(Keccak::KECCAK_STATE_SIZE);
	std::vector<std::vector<uint8_t>> buf(4);
    __m256i f;
    size_t ctr0;
    size_t ctr1;
    size_t ctr2;
    size_t ctr3;
	
	buf[0].resize(864);
	buf[1].resize(864);
	buf[2].resize(864);
	buf[3].resize(864);

    f = _mm256_loadu_si256((__m256i*)Seed.data());
    _mm256_store_si256((__m256i*)buf[0].data(), f);
    _mm256_store_si256((__m256i*)buf[1].data(), f);
    _mm256_store_si256((__m256i*)buf[2].data(), f);
    _mm256_store_si256((__m256i*)buf[3].data(), f);

    buf[0][DILITHIUM_SEED_SIZE] = (uint8_t)Nonce0;
    buf[0][DILITHIUM_SEED_SIZE + 1] = (uint8_t)(Nonce0 >> 8);
    buf[1][DILITHIUM_SEED_SIZE] = (uint8_t)Nonce1;
    buf[1][DILITHIUM_SEED_SIZE + 1] = (uint8_t)(Nonce1 >> 8);
    buf[2][DILITHIUM_SEED_SIZE] = (uint8_t)Nonce2;
    buf[2][DILITHIUM_SEED_SIZE + 1] = (uint8_t)(Nonce2 >> 8);
    buf[3][DILITHIUM_SEED_SIZE] = (uint8_t)Nonce3;
    buf[3][DILITHIUM_SEED_SIZE + 1] = (uint8_t)(Nonce3 >> 8);

    Keccak::AbsorbR24x1600H(ksi, Keccak::KECCAK128_RATE_SIZE, buf[0], buf[1], buf[2], buf[3], DILITHIUM_SEED_SIZE + 2, Keccak::KECCAK_SHAKE_DOMAIN);
    Keccak::SqueezeBlocksR24x1600H(ksi, Keccak::KECCAK128_RATE_SIZE, buf[0], buf[1], buf[2], buf[3], 5);

    ctr0 = RejUniformAvx2(A0, 0, A0.size(), buf[0], buf[0].size());
    ctr1 = RejUniformAvx2(A1, 0, A1.size(), buf[1], buf[1].size());
    ctr2 = RejUniformAvx2(A2, 0, A2.size(), buf[2], buf[2].size());
    ctr3 = RejUniformAvx2(A3, 0, A3.size(), buf[3], buf[3].size());

    while (ctr0 < DILITHIUM_N || ctr1 < DILITHIUM_N || ctr2 < DILITHIUM_N || ctr3 < DILITHIUM_N)
    {
        Keccak::SqueezeBlocksR24x1600H(ksi, Keccak::KECCAK128_RATE_SIZE, buf[0], buf[1], buf[2], buf[3], 1);

        ctr0 += RejUniform(A0, ctr0, DILITHIUM_N - ctr0, buf[0], Keccak::KECCAK128_RATE_SIZE);
        ctr1 += RejUniform(A1, ctr1, DILITHIUM_N - ctr1, buf[1], Keccak::KECCAK128_RATE_SIZE);
        ctr2 += RejUniform(A2, ctr2, DILITHIUM_N - ctr2, buf[2], Keccak::KECCAK128_RATE_SIZE);
        ctr3 += RejUniform(A3, ctr3, DILITHIUM_N - ctr3, buf[3], Keccak::KECCAK128_RATE_SIZE);
    }
}

void DLTMPolyMath::PolyUniformEta4x(std::array<int32_t, 256> &A0, std::array<int32_t, 256> &A1, std::array<int32_t, 256> &A2, std::array<int32_t, 256> &A3,
    const std::vector<uint8_t> &Seed, uint16_t Nonce0, uint16_t Nonce1, uint16_t Nonce2, uint16_t Nonce3, size_t Blocks, uint32_t Eta)
{
    std::vector<__m256i> ksi(Keccak::KECCAK_STATE_SIZE);
	std::vector<std::vector<uint8_t>> buf(4);
    __m256i f;
    size_t ctr0;
    size_t ctr1;
    size_t ctr2;
    size_t ctr3;

	if (Eta == 2)
	{
		buf[0].resize(192);
		buf[1].resize(192);
		buf[2].resize(192);
		buf[3].resize(192);
	}
	else
	{
		buf[0].resize(352);
		buf[1].resize(352);
		buf[2].resize(352);
		buf[3].resize(352);
	}

    f = _mm256_load_si256((__m256i*)Seed.data());
    _mm256_store_si256((__m256i*)buf[0].data(), f);
    _mm256_store_si256((__m256i*)buf[1].data(), f);
    _mm256_store_si256((__m256i*)buf[2].data(), f);
    _mm256_store_si256((__m256i*)buf[3].data(), f);

    buf[0][DILITHIUM_SEED_SIZE] = (uint8_t)Nonce0;
    buf[0][DILITHIUM_SEED_SIZE + 1] = (uint8_t)(Nonce0 >> 8);
    buf[1][DILITHIUM_SEED_SIZE] = (uint8_t)Nonce1;
    buf[1][DILITHIUM_SEED_SIZE + 1] = (uint8_t)(Nonce1 >> 8);
    buf[2][DILITHIUM_SEED_SIZE] = (uint8_t)Nonce2;
    buf[2][DILITHIUM_SEED_SIZE + 1] = (uint8_t)(Nonce2 >> 8);
    buf[3][DILITHIUM_SEED_SIZE] = (uint8_t)Nonce3;
    buf[3][DILITHIUM_SEED_SIZE + 1] = (uint8_t)(Nonce3 >> 8);

    Keccak::AbsorbR24x1600H(ksi, Keccak::KECCAK128_RATE_SIZE, buf[0], buf[1], buf[2], buf[3], Seed.size() + 2, Keccak::KECCAK_SHAKE_DOMAIN);
    Keccak::SqueezeBlocksR24x1600H(ksi, Keccak::KECCAK128_RATE_SIZE, buf[0], buf[1], buf[2], buf[3], Blocks);

    ctr0 = RejEta(A0, 0, DILITHIUM_N, buf[0], Blocks * Keccak::KECCAK128_RATE_SIZE, Eta);
    ctr1 = RejEta(A1, 0, DILITHIUM_N, buf[1], Blocks * Keccak::KECCAK128_RATE_SIZE, Eta);
    ctr2 = RejEta(A2, 0, DILITHIUM_N, buf[2], Blocks * Keccak::KECCAK128_RATE_SIZE, Eta);
    ctr3 = RejEta(A3, 0, DILITHIUM_N, buf[3], Blocks * Keccak::KECCAK128_RATE_SIZE, Eta);

    while (ctr0 < DILITHIUM_N || ctr1 < DILITHIUM_N || ctr2 < DILITHIUM_N || ctr3 < DILITHIUM_N)
    {
        Keccak::SqueezeBlocksR24x1600H(ksi, Keccak::KECCAK128_RATE_SIZE, buf[0], buf[1], buf[2], buf[3], 1);

        ctr0 += RejEta(A0, ctr0, DILITHIUM_N - ctr0, buf[0], Keccak::KECCAK128_RATE_SIZE, Eta);
        ctr1 += RejEta(A1, ctr1, DILITHIUM_N - ctr1, buf[1], Keccak::KECCAK128_RATE_SIZE, Eta);
        ctr2 += RejEta(A2, ctr2, DILITHIUM_N - ctr2, buf[2], Keccak::KECCAK128_RATE_SIZE, Eta);
        ctr3 += RejEta(A3, ctr3, DILITHIUM_N - ctr3, buf[3], Keccak::KECCAK128_RATE_SIZE, Eta);
    }
}

void DLTMPolyMath::PolyUniformGamma1x4(std::array<int32_t, 256> &A0, std::array<int32_t, 256> &A1, std::array<int32_t, 256> &A2, std::array<int32_t, 256> &A3,
    const std::vector<uint8_t> &Seed, uint16_t Nonce0, uint16_t Nonce1, uint16_t Nonce2, uint16_t Nonce3, uint32_t Gamma1)
{
    std::vector<__m256i> ksi(Keccak::KECCAK_STATE_SIZE);
	std::vector<std::vector<uint8_t>> buf(4);
    __m256i f;
    __m128i g;

	buf[0].resize(704);
	buf[1].resize(704);
	buf[2].resize(704);
	buf[3].resize(704);

    f = _mm256_load_si256((__m256i*)Seed.data());
    _mm256_store_si256((__m256i*)buf[0].data(), f);
    _mm256_store_si256((__m256i*)buf[1].data(), f);
    _mm256_store_si256((__m256i*)buf[2].data(), f);
    _mm256_store_si256((__m256i*)buf[3].data(), f);
    g = _mm_load_si128((__m128i*)&Seed[32]);
    _mm_store_si128((__m128i*)&buf[0][32], g);
    _mm_store_si128((__m128i*)&buf[1][32], g);
    _mm_store_si128((__m128i*)&buf[2][32], g);
    _mm_store_si128((__m128i*)&buf[3][32], g);

    buf[0][DILITHIUM_CRH_SIZE] = (uint8_t)Nonce0;
    buf[0][DILITHIUM_CRH_SIZE + 1] = (uint8_t)(Nonce0 >> 8);
    buf[1][DILITHIUM_CRH_SIZE] = (uint8_t)Nonce1;
    buf[1][DILITHIUM_CRH_SIZE + 1] = (uint8_t)(Nonce1 >> 8);
    buf[2][DILITHIUM_CRH_SIZE] = (uint8_t)Nonce2;
    buf[2][DILITHIUM_CRH_SIZE + 1] = (uint8_t)(Nonce2 >> 8);
    buf[3][DILITHIUM_CRH_SIZE] = (uint8_t)Nonce3;
    buf[3][DILITHIUM_CRH_SIZE + 1] = (uint8_t)(Nonce3 >> 8);

    Keccak::AbsorbR24x1600H(ksi, Keccak::KECCAK256_RATE_SIZE, buf[0], buf[1], buf[2], buf[3], DILITHIUM_CRH_SIZE + 2, Keccak::KECCAK_SHAKE_DOMAIN);
    Keccak::SqueezeBlocksR24x1600H(ksi, Keccak::KECCAK256_RATE_SIZE, buf[0], buf[1], buf[2], buf[3], 5);

    PolyZUnpack(A0, buf[0], 0, Gamma1);
    PolyZUnpack(A1, buf[1], 0, Gamma1);
    PolyZUnpack(A2, buf[2], 0, Gamma1);
    PolyZUnpack(A3, buf[3], 0, Gamma1);
}

void DLTMPolyMath::PolyW1Pack(std::vector<uint8_t> &R, size_t ROffset, const std::array<int32_t, 256> &A, uint32_t Gamma2)
{
	if (Gamma2 == (DILITHIUM_Q - 1) / 88)
	{
		for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
		{
			R[ROffset + (3 * i)] = A[4 * i];
			R[ROffset + (3 * i)] |= A[4 * i + 1] << 6;
			R[ROffset + (3 * i) + 1] = A[4 * i + 1] >> 2;
			R[ROffset + (3 * i) + 1] |= A[4 * i + 2] << 4;
			R[ROffset + (3 * i) + 2] = A[4 * i + 2] >> 4;
			R[ROffset + (3 * i) + 2] |= A[4 * i + 3] << 2;
		}
	}
	else if (Gamma2 == (DILITHIUM_Q - 1) / 32)
	{
		const __m256i mask = _mm256_set1_epi64x(0xFF00FF00FF00FF00);
		const __m256i idx = _mm256_set_epi8(15, 13, 14, 12, 11, 9, 10, 8, 7, 5, 6, 4, 3, 1, 2, 0,
			15, 13, 14, 12, 11, 9, 10, 8, 7, 5, 6, 4, 3, 1, 2, 0);
		__m256i f0;
		__m256i f1;
		__m256i f2;
		__m256i f3;
		__m256i f4;
		__m256i f5;
		__m256i f6;
		__m256i f7;
		size_t i;

		for (i = 0; i < DILITHIUM_N / 64; ++i)
		{
			f0 = _mm256_load_si256((__m256i*)&A[64 * i]);
			f1 = _mm256_load_si256((__m256i*)&A[64 * i + 8]);
			f2 = _mm256_load_si256((__m256i*)&A[64 * i + 16]);
			f3 = _mm256_load_si256((__m256i*)&A[64 * i + 24]);

			f0 = _mm256_and_si256(f0, _mm256_set1_epi32(15));
			f1 = _mm256_and_si256(f1, _mm256_set1_epi32(15));
			f2 = _mm256_and_si256(f2, _mm256_set1_epi32(15));
			f3 = _mm256_and_si256(f3, _mm256_set1_epi32(15));

			f0 = _mm256_packus_epi32(f0, f1);
			f4 = _mm256_load_si256((__m256i*)&A[64 * i + 32]);
			f5 = _mm256_load_si256((__m256i*)&A[64 * i + 40]);

			f1 = _mm256_packus_epi32(f2, f3);
			f6 = _mm256_load_si256((__m256i*)&A[64 * i + 48]);
			f7 = _mm256_load_si256((__m256i*)&A[64 * i + 56]);

			f4 = _mm256_and_si256(f4, _mm256_set1_epi32(15));
			f5 = _mm256_and_si256(f5, _mm256_set1_epi32(15));
			f6 = _mm256_and_si256(f6, _mm256_set1_epi32(15));
			f7 = _mm256_and_si256(f7, _mm256_set1_epi32(15));

			f2 = _mm256_packus_epi32(f4, f5);
			f3 = _mm256_packus_epi32(f6, f7);
			f0 = _mm256_packus_epi16(f0, f1);
			f1 = _mm256_packus_epi16(f2, f3);
			f2 = _mm256_permute2x128_si256(f0, f1, 0x20);	// ABCD
			f3 = _mm256_permute2x128_si256(f0, f1, 0x31);	// EFGH

			f4 = _mm256_srli_epi16(f2, 8);					// B0D0
			f5 = _mm256_slli_epi16(f3, 8);					// 0E0G
			f0 = _mm256_blendv_epi8(f2, f5, mask);			// AECG
			f1 = _mm256_blendv_epi8(f4, f3, mask);			// BFDH

			f1 = _mm256_slli_epi16(f1, 4);
			f0 = _mm256_add_epi16(f0, f1);

			f0 = _mm256_shuffle_epi8(f0, idx);
			_mm256_storeu_si256((__m256i*)&R[ROffset + (32 * i)], f0);
		}
    }
}

void DLTMPolyMath::PolyVecMatrixExpandAvx2(std::vector<std::vector<std::array<int32_t, 256>>> &Matrix, const std::vector<uint8_t> &Rho, uint32_t K, uint32_t L)
{
	if (K == 4 && L == 4)
	{
		PolyUniform4x(Matrix[0][0], Matrix[0][1], Matrix[0][2], Matrix[0][3], Rho, 0, 1, 2, 3);
		PolyUniform4x(Matrix[1][0], Matrix[1][1], Matrix[1][2], Matrix[1][3], Rho, 256, 257, 258, 259);
		PolyUniform4x(Matrix[2][0], Matrix[2][1], Matrix[2][2], Matrix[2][3], Rho, 512, 513, 514, 515);
		PolyUniform4x(Matrix[3][0], Matrix[3][1], Matrix[3][2], Matrix[3][3], Rho, 768, 769, 770, 771);
	}
	else if (K == 6 && L == 5)
	{
		std::array<int32_t, 256> t0;
		std::array<int32_t, 256> t1;
		PolyUniform4x(Matrix[0][0], Matrix[0][1], Matrix[0][2], Matrix[0][3], Rho, 0, 1, 2, 3);
		PolyUniform4x(Matrix[0][4], Matrix[1][0], Matrix[1][1], Matrix[1][2], Rho, 4, 256, 257, 258);
		PolyUniform4x(Matrix[1][3], Matrix[1][4], Matrix[2][0], Matrix[2][1], Rho, 259, 260, 512, 513);
		PolyUniform4x(Matrix[2][2], Matrix[2][3], Matrix[2][4], Matrix[3][0], Rho, 514, 515, 516, 768);
		PolyUniform4x(Matrix[3][1], Matrix[3][2], Matrix[3][3], Matrix[3][4], Rho, 769, 770, 771, 772);
		PolyUniform4x(Matrix[4][0], Matrix[4][1], Matrix[4][2], Matrix[4][3], Rho, 1024, 1025, 1026, 1027);
		PolyUniform4x(Matrix[4][4], Matrix[5][0], Matrix[5][1], Matrix[5][2], Rho, 1028, 1280, 1281, 1282);
		PolyUniform4x(Matrix[5][3], Matrix[5][4], t0, t1, Rho, 1283, 1284, 0, 0);
	}
	else if (K == 8 && L == 7)
	{
		PolyUniform4x(Matrix[0][0], Matrix[0][1], Matrix[0][2], Matrix[0][3], Rho, 0, 1, 2, 3);
		PolyUniform4x(Matrix[0][4], Matrix[0][5], Matrix[0][6], Matrix[1][0], Rho, 4, 5, 6, 256);
		PolyUniform4x(Matrix[1][1], Matrix[1][2], Matrix[1][3], Matrix[1][4], Rho, 257, 258, 259, 260);
		PolyUniform4x(Matrix[1][5], Matrix[1][6], Matrix[2][0], Matrix[2][1], Rho, 261, 262, 512, 513);
		PolyUniform4x(Matrix[2][2], Matrix[2][3], Matrix[2][4], Matrix[2][5], Rho, 514, 515, 516, 517);
		PolyUniform4x(Matrix[2][6], Matrix[3][0], Matrix[3][1], Matrix[3][2], Rho, 518, 768, 769, 770);
		PolyUniform4x(Matrix[3][3], Matrix[3][4], Matrix[3][5], Matrix[3][6], Rho, 771, 772, 773, 774);
		PolyUniform4x(Matrix[4][0], Matrix[4][1], Matrix[4][2], Matrix[4][3], Rho, 1024, 1025, 1026, 1027);
		PolyUniform4x(Matrix[4][4], Matrix[4][5], Matrix[4][6], Matrix[5][0], Rho, 1028, 1029, 1030, 1280);
		PolyUniform4x(Matrix[5][1], Matrix[5][2], Matrix[5][3], Matrix[5][4], Rho, 1281, 1282, 1283, 1284);
		PolyUniform4x(Matrix[5][5], Matrix[5][6], Matrix[6][0], Matrix[6][1], Rho, 1285, 1286, 1536, 1537);
		PolyUniform4x(Matrix[6][2], Matrix[6][3], Matrix[6][4], Matrix[6][5], Rho, 1538, 1539, 1540, 1541);
		PolyUniform4x(Matrix[6][6], Matrix[7][0], Matrix[7][1], Matrix[7][2], Rho, 1542, 1792, 1793, 1794);
		PolyUniform4x(Matrix[7][3], Matrix[7][4], Matrix[7][5], Matrix[7][6], Rho, 1795, 1796, 1797, 1798);
	}
}

void DLTMPolyMath::PolyVecMatrixExpandRow(std::vector<std::vector<std::array<int32_t, 256>>> &Matrix, const std::vector<uint8_t> &Rho, uint32_t K, uint32_t L, size_t Index)
{
	if (K == 4 && L == 4)
	{
		if (Index == 0)
		{
			PolyUniform4x(Matrix[0][0], Matrix[0][1], Matrix[0][2], Matrix[0][3], Rho, 0, 1, 2, 3);
		}
		if (Index == 1)
		{
			PolyUniform4x(Matrix[1][0], Matrix[1][1], Matrix[1][2], Matrix[1][3], Rho, 256, 257, 258, 259);
		}
		if (Index == 2)
		{
			PolyUniform4x(Matrix[2][0], Matrix[2][1], Matrix[2][2], Matrix[2][3], Rho, 512, 513, 514, 515);
		}
		if (Index == 3)
		{
			PolyUniform4x(Matrix[3][0], Matrix[3][1], Matrix[3][2], Matrix[3][3], Rho, 768, 769, 770, 771);
		}
	}
	else if (K == 6 && L == 5)
	{
		if (Index == 0)
		{
			PolyUniform4x(Matrix[0][0], Matrix[0][1], Matrix[0][2], Matrix[0][3], Rho, 0, 1, 2, 3);
			PolyUniform4x(Matrix[0][4], Matrix[1][0], Matrix[1][1], Matrix[1][2], Rho, 4, 256, 257, 258);
		}
		if (Index == 1)
		{
			PolyUniform4x(Matrix[1][3], Matrix[1][4], Matrix[2][0], Matrix[2][1], Rho, 259, 260, 512, 513);
		}
		if (Index == 2)
		{
			PolyUniform4x(Matrix[2][2], Matrix[2][3], Matrix[2][4], Matrix[3][0], Rho, 514, 515, 516, 768);
		}
		if (Index == 3)
		{
			PolyUniform4x(Matrix[3][1], Matrix[3][2], Matrix[3][3], Matrix[3][4], Rho, 769, 770, 771, 772);
		}
		if (Index == 4)
		{
			PolyUniform4x(Matrix[4][0], Matrix[4][1], Matrix[4][2], Matrix[4][3], Rho, 1024, 1025, 1026, 1027);
			PolyUniform4x(Matrix[4][4], Matrix[5][0], Matrix[5][1], Matrix[5][2], Rho, 1028, 1280, 1281, 1282);
		}
		if (Index == 5)
		{
			std::array<int32_t, 256> t0;
			std::array<int32_t, 256> t1;

			PolyUniform4x(Matrix[5][3], Matrix[5][4], t0, t1, Rho, 1283, 1284, 0, 0);
		}
	}
	else if (K == 8 && L == 7)
	{
		if (Index == 0)
		{
			PolyUniform4x(Matrix[0][0], Matrix[0][1], Matrix[0][2], Matrix[0][3], Rho, 0, 1, 2, 3);
			PolyUniform4x(Matrix[0][4], Matrix[0][5], Matrix[0][6], Matrix[1][0], Rho, 4, 5, 6, 256);
		}
		if (Index == 1)
		{
			PolyUniform4x(Matrix[1][1], Matrix[1][2], Matrix[1][3], Matrix[1][4], Rho, 257, 258, 259, 260);
			PolyUniform4x(Matrix[1][5], Matrix[1][6], Matrix[2][0], Matrix[2][1], Rho, 261, 262, 512, 513);
		}
		if (Index == 2)
		{
			PolyUniform4x(Matrix[2][2], Matrix[2][3], Matrix[2][4], Matrix[2][5], Rho, 514, 515, 516, 517);
			PolyUniform4x(Matrix[2][6], Matrix[3][0], Matrix[3][1], Matrix[3][2], Rho, 518, 768, 769, 770);
		}
		if (Index == 3)
		{
			PolyUniform4x(Matrix[3][3], Matrix[3][4], Matrix[3][5], Matrix[3][6], Rho, 771, 772, 773, 774);
		}
		if (Index == 4)
		{
			PolyUniform4x(Matrix[4][0], Matrix[4][1], Matrix[4][2], Matrix[4][3], Rho, 1024, 1025, 1026, 1027);
			PolyUniform4x(Matrix[4][4], Matrix[4][5], Matrix[4][6], Matrix[5][0], Rho, 1028, 1029, 1030, 1280);
		}
		if (Index == 5)
		{
			PolyUniform4x(Matrix[5][1], Matrix[5][2], Matrix[5][3], Matrix[5][4], Rho, 1281, 1282, 1283, 1284);
			PolyUniform4x(Matrix[5][5], Matrix[5][6], Matrix[6][0], Matrix[6][1], Rho, 1285, 1286, 1536, 1537);
		}
		if (Index == 6)
		{
			PolyUniform4x(Matrix[6][2], Matrix[6][3], Matrix[6][4], Matrix[6][5], Rho, 1538, 1539, 1540, 1541);
			PolyUniform4x(Matrix[6][6], Matrix[7][0], Matrix[7][1], Matrix[7][2], Rho, 1542, 1792, 1793, 1794);
		}
		if (Index == 7)
		{
			PolyUniform4x(Matrix[7][3], Matrix[7][4], Matrix[7][5], Matrix[7][6], Rho, 1795, 1796, 1797, 1798);
		}
	}
}

#else

void DLTMPolyMath::PolyAdd(std::array<int32_t, 256> &C, const std::array<int32_t, 256> &A, const std::array<int32_t, 256> &B)
{
	for (size_t i = 0; i < C.size(); ++i)
	{
		C[i] = A[i] + B[i];
	}
}

void DLTMPolyMath::PolyCaddQ(std::array<int32_t, 256> &A)
{
    for (size_t i = 0; i < A.size(); ++i)
    {
        A[i] = CaddQ(A[i]);
    }
}

int32_t DLTMPolyMath::PolyChkNorm(const std::array<int32_t, 256> &A, uint32_t B)
{
	int32_t t;
    int32_t res;

    res = 0;

    if (B > (DILITHIUM_Q - 1) / 8)
    {
        res = 1;
    }
    else
    {
        // It is ok to leak which coefficient violates the bound since
        // the probability for each coefficient is independent of secret
        // data but we must not leak the sign of the centralized representative.
        for (size_t i = 0; i < DILITHIUM_N; ++i)
        {
            // absolute value
            t = A[i] >> 31;
            t = A[i] - (t & 2 * A[i]);

            if (t >= (int32_t)B)
            {
                res = 1;
                break;
            }
        }
    }

    return res;
}


void DLTMPolyMath::PolyDecompose(std::array<int32_t, 256> &A1, std::array<int32_t, 256> &A0, const std::array<int32_t, 256> &A, uint32_t Gamma2)
{
	size_t i;

	for (i = 0; i < A1.size(); ++i)
	{
		A1[i] = Decompose(A0[i], A[i], Gamma2);
	}
}

uint32_t DLTMPolyMath::PolyMakeHint(std::array<int32_t, 256> &H, const std::array<int32_t, 256> &A0, const std::array<int32_t, 256> &A1, uint32_t Gamma2)
{
    uint32_t s;

    s = 0;

    for (size_t i = 0; i < H.size(); ++i)
    {
        H[i] = MakeHint(A0[i], A1[i], Gamma2);
        s += H[i];
    }

    return s;
}

void DLTMPolyMath::PolyPower2Round(std::array<int32_t, 256> &A1, std::array<int32_t, 256> &A0, const std::array<int32_t, 256> &A)
{
	size_t i;

	for (i = 0; i < A1.size(); ++i)
	{
		A1[i] = Power2Round(A[i], A0[i]);
	}
}

void DLTMPolyMath::PolyReduce(std::array<int32_t, 256> &A)
{
	size_t i;

	for (i = 0; i < A.size(); ++i)
	{
		A[i] = Reduce32(A[i]);
	}
}

void DLTMPolyMath::PolyShiftL(std::array<int32_t, 256> &A)
{
	size_t i;

	for (i = 0; i < A.size(); ++i)
	{
		A[i] <<= DILITHIUM_D;
	}
}

void DLTMPolyMath::PolySub(std::array<int32_t, 256> &C, const std::array<int32_t, 256> &A, const std::array<int32_t, 256> &B)
{
	size_t i;

	for (i = 0; i < C.size(); ++i)
	{
		C[i] = A[i] - B[i];
	}
}

void DLTMPolyMath::PolyUseHint(std::array<int32_t, 256> &B, const std::array<int32_t, 256> &A, const std::array<int32_t, 256> &H, uint32_t Gamma2)
{
	size_t i;

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        B[i] = UseHint(A[i], H[i], Gamma2);
    }
}

void DLTMPolyMath::PolyW1Pack(std::vector<uint8_t> &R, size_t ROffset, const std::array<int32_t, 256> &A, uint32_t Gamma2)
{
	size_t i;

	if (Gamma2 == (DILITHIUM_Q - 1) / 88)
	{
		for (i = 0; i < DILITHIUM_N / 4; ++i)
		{
			R[ROffset + 3 * i] = (uint8_t)A[4 * i];
			R[ROffset + 3 * i] |= (uint8_t)(A[(4 * i) + 1] << 6);
			R[ROffset + (3 * i) + 1] = (uint8_t)(A[(4 * i) + 1] >> 2);
			R[ROffset + (3 * i) + 1] |= (uint8_t)(A[(4 * i) + 2] << 4);
			R[ROffset + (3 * i) + 2] = (uint8_t)(A[(4 * i) + 2] >> 4);
			R[ROffset + (3 * i) + 2] |= (uint8_t)(A[(4 * i) + 3] << 2);
		}
	}
	else if (Gamma2 == (DILITHIUM_Q - 1) / 32)
	{
		for (i = 0; i < DILITHIUM_N / 2; ++i)
		{
			R[ROffset + i] = (uint8_t)(A[2 * i] | (A[(2 * i) + 1] << 4));
		}
	}
}

void DLTMPolyMath::PolyVecPackW1(std::vector<uint8_t> &R, const std::vector<std::array<int32_t, 256>> &W1, size_t W1PackedSize, uint32_t Gamma2)
{
	size_t i;

    for (size_t i = 0; i < W1.size(); ++i)
    {
        PolyW1Pack(R, i * W1PackedSize, W1[i], Gamma2);
    }
}

#endif

// ntt.c //

void DLTMPolyMath::InvNttToMont(std::array<int32_t, 256> &A)
{
    const int32_t F = 41978; // mont ^ 2 / 256
	size_t j;
    size_t k;
	size_t len;
    int32_t t;
    int32_t zeta;

    k = 256;

    for (len = 1; len < DILITHIUM_N; len <<= 1)
    {
        for (size_t start = 0; start < DILITHIUM_N; start = j + len)
        {
            --k;
            zeta = ~Zetas[k] + 1;

            for (j = start; j < start + len; ++j)
            {
                t = A[j];
                A[j] = t + A[j + len];
                A[j + len] = t - A[j + len];
                A[j + len] = MontReduce((int64_t)zeta * A[j + len]);
            }
        }
    }

    for (j = 0; j < DILITHIUM_N; ++j)
    {
        A[j] = MontReduce((int64_t)F * A[j]);
    }
}

void DLTMPolyMath::Ntt(std::array<int32_t, 256> &A)
{
	size_t j;
    size_t k;
	size_t len;
    int32_t zeta;
    int32_t t;

    k = 0;

    for (len = 128; len > 0; len >>= 1)
    {
        for (size_t start = 0; start < DILITHIUM_N; start = j + len)
        {
            ++k;
            zeta = Zetas[k];

            for (j = start; j < start + len; ++j)
            {
                t = MontReduce((int64_t)zeta * A[j + len]);
                A[j + len] = A[j] - t;
                A[j] = A[j] + t;
            }
        }
    }
}

// packing.c //

void DLTMPolyMath::PackPk(std::vector<uint8_t> &Pk, const std::vector<uint8_t> &Rho, const std::vector<std::array<int32_t, 256>> &T1, uint32_t PolT1Packed)
{
	size_t i;

    for (i = 0; i < Rho.size(); ++i)
    {
        Pk[i] = Rho[i];
    }

    for (i = 0; i < T1.size(); ++i)
    {
        PolyT1Pack(Pk, Rho.size() + (i * PolT1Packed), T1[i]);
    }
}

void DLTMPolyMath::UnpackPk(std::vector<uint8_t> &Rho, std::vector<std::array<int32_t, 256>> &T1, const std::vector<uint8_t> &Pk, uint32_t PolT1Packed)
{
	size_t i;
	size_t poff;

	MemoryTools::Copy(Pk, 0, Rho, 0, Rho.size());

	poff = Rho.size();

	for (i = 0; i < T1.size(); ++i)
	{
		PolyT1Unpack(T1[i], Pk, poff + (i * PolT1Packed));
	}
}

void DLTMPolyMath::PackSk(std::vector<uint8_t> &Sk, const std::vector<uint8_t> &Rho, const std::vector<uint8_t> &Key, const std::vector<uint8_t> &Tr, const std::vector<std::array<int32_t, 256>> &S1,
	const std::vector<std::array<int32_t, 256>> &S2, const std::vector<std::array<int32_t, 256>> &T0, uint32_t Eta, uint32_t PolTAPacked, uint32_t PolT0Packed)
{
	size_t i;
	size_t soff;

	MemoryTools::Copy(Rho, 0, Sk, 0, Rho.size());
	soff = Rho.size();
	MemoryTools::Copy(Key, 0, Sk, soff, Key.size());
	soff += Key.size();
	MemoryTools::Copy(Tr, 0, Sk, soff, Tr.size());
	soff += Tr.size();

	for (i = 0; i < S1.size(); ++i)
	{
		PolyEtaPack(Sk, soff + (i * PolTAPacked), S1[i], Eta);
	}

	soff += S1.size() * PolTAPacked;

	for (i = 0; i < S2.size(); ++i)
	{
		PolyEtaPack(Sk, soff + (i * PolTAPacked), S2[i], Eta);
	}

	soff += T0.size() * PolTAPacked;

	for (i = 0; i < T0.size(); ++i)
	{
		PolyT0Pack(Sk, soff + (i * PolT0Packed), T0[i]);
	}
}

void DLTMPolyMath::UnpackSk(std::vector<uint8_t> &Rho, std::vector<uint8_t> &Tr, std::vector<uint8_t> &Key, std::vector<std::array<int32_t, 256>> &T0, 
	std::vector<std::array<int32_t, 256>> &S1, std::vector<std::array<int32_t, 256>> &S2, const std::vector<uint8_t> &Sk, uint32_t Eta, uint32_t PolyEtaPacked, uint32_t PolyT0Packed)
{
	size_t i;
	size_t soff;

	MemoryTools::Copy(Sk, 0, Rho, 0, DILITHIUM_SEED_SIZE);
	soff = DILITHIUM_SEED_SIZE;
	MemoryTools::Copy(Sk, soff, Key, 0, DILITHIUM_SEED_SIZE);
	soff += DILITHIUM_SEED_SIZE;
	MemoryTools::Copy(Sk, soff, Tr, 0, DILITHIUM_CRH_SIZE);
	soff += DILITHIUM_CRH_SIZE;

	for (i = 0; i < S1.size(); ++i)
	{
		PolyEtaUnpack(S1[i], Sk, soff + (i * PolyEtaPacked), Eta);
	}

	soff += S1.size() * PolyEtaPacked;

	for (i = 0; i < S2.size(); ++i)
	{
		PolyEtaUnpack(S2[i], Sk, soff + (i * PolyEtaPacked), Eta);
	}

	soff += S2.size() * PolyEtaPacked;

	for (i = 0; i < T0.size(); ++i)
	{
		PolyT0Unpack(T0[i], Sk, soff + (i * PolyT0Packed));
	}
}

void DLTMPolyMath::PackSig(std::vector<uint8_t> &Signature, const std::vector<uint8_t> &C, const std::vector<std::array<int32_t, 256>> &Z, 
	const std::vector<std::array<int32_t, 256>> &H, uint32_t K, uint32_t Omega, uint32_t PolyzPacked, uint32_t Gamma1)
{
    size_t i;
    size_t j;
    size_t k;
	size_t pos;

    for (i = 0; i < DILITHIUM_SEED_SIZE; ++i)
    {
        Signature[i] = C[i];
    }
	
    pos = DILITHIUM_SEED_SIZE;

    for (i = 0; i < Z.size(); ++i)
    {
        PolyZPack(Signature, pos + (i * PolyzPacked), Z[i], Gamma1);
    }

    pos += Z.size() * PolyzPacked;

    // encode h

    k = 0;
	MemoryTools::Clear(Signature, pos, Omega + K);

    for (i = 0; i < K; ++i)
    {
        for (j = 0; j < DILITHIUM_N; ++j)
        {
            if (H[i][j] != 0)
            {
				if (pos + k == 2420)
				{
					break;
				}
                Signature[pos + k] = (uint8_t)j;
                ++k;
            }
        }
		
        Signature[pos + Omega + i] = (uint8_t)k;
    }
}

int32_t DLTMPolyMath::UnpackSig(std::vector<uint8_t> &C, std::vector<std::array<int32_t, 256>> &Z, std::vector<std::array<int32_t, 256>> &H, 
	const std::vector<uint8_t> &Signature, uint32_t PolZPacked, uint32_t Gamma1, uint32_t Omega)
{
	size_t i;
    size_t j;
    size_t k;
	size_t pos;
    int32_t res;

    res = 0;

    MemoryTools::Copy(Signature, 0, C, 0, DILITHIUM_SEED_SIZE);
    pos = DILITHIUM_SEED_SIZE;

    for (i = 0; i < Z.size(); ++i)
    {
        PolyZUnpack(Z[i], Signature, pos + (i * PolZPacked), Gamma1);
    }

    pos += Z.size() * PolZPacked;

    // decode h
    k = 0;

    for (i = 0; i < H.size(); ++i)
    {
        for (j = 0; j < DILITHIUM_N; ++j)
        {
            H[i][j] = 0;
        }

        if (Signature[pos + Omega + i] < k || Signature[pos + Omega + i] > Omega)
        {
            res = 1;
            break;
        }

        for (j = k; j < Signature[pos + Omega + i]; ++j)
        {
            // coefficients are ordered for strong unforgeability
            if (j > k && Signature[pos + j] <= Signature[pos + j - 1])
            {
                res = 1;
                break;
            }

            H[i][Signature[pos + j]] = 1;
        }

        if (res != 0)
        {
            break;
        }

        k = Signature[pos + Omega + i];
    }

    if (res == 0)
    {
        // extra indices are zero for strong unforgeability
        for (j = k; j < Omega; ++j)
        {
            if (Signature[pos + j] != 0)
            {
                res = 1;
                break;
            }
        }
    }

    return res;
}

// poly.c //

void DLTMPolyMath::PolyChallenge(std::array<int32_t, 256> &C, const std::vector<uint8_t> &Seed, uint32_t Tau)
{
    std::vector<uint8_t> buf(Keccak::KECCAK256_RATE_SIZE);
	std::array<uint64_t, 25> kctx = { 0 };
    uint64_t signs;
    size_t i;
    size_t b;
    size_t pos;

	Keccak::Incremental(Seed, 0, DILITHIUM_SEED_SIZE, 0, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx, true);
	Keccak::SqueezePartial(kctx, buf, 0, buf.size(), Keccak::KECCAK256_RATE_SIZE);

    signs = 0;
    pos = 8;

    for (i = 0; i < 8; ++i)
    {
        signs |= (uint64_t)buf[i] << (8 * i);
    }

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        C[i] = 0;
    }

    for (i = DILITHIUM_N - Tau; i < DILITHIUM_N; ++i)
    {
        do
        {
            if (pos >= Keccak::KECCAK256_RATE_SIZE)
            {
                Keccak::Squeeze(kctx, buf, 0, 1, Keccak::KECCAK256_RATE_SIZE);
                pos = 0;
            }

            b = buf[pos];
            ++pos;
        } 
		while (b > i);

        C[i] = C[b];
        C[b] = 1 - (2 * (signs & 1));
        signs >>= 1;
    }
}

void DLTMPolyMath::PolyEtaPack(std::vector<uint8_t> &R, size_t ROffset, const std::array<int32_t, 256> &A, uint32_t Eta)
{
	std::array<uint8_t, 8> t;

	if (Eta == 2)
	{
		for (size_t i = 0; i < A.size() / 8; ++i)
		{
			t[0] = (uint8_t)(Eta - A[8 * i]);
			t[1] = (uint8_t)(Eta - A[(8 * i) + 1]);
			t[2] = (uint8_t)(Eta - A[(8 * i) + 2]);
			t[3] = (uint8_t)(Eta - A[(8 * i) + 3]);
			t[4] = (uint8_t)(Eta - A[(8 * i) + 4]);
			t[5] = (uint8_t)(Eta - A[(8 * i) + 5]);
			t[6] = (uint8_t)(Eta - A[(8 * i) + 6]);
			t[7] = (uint8_t)(Eta - A[(8 * i) + 7]);

			R[ROffset + (3 * i)] = (uint8_t)((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
			R[ROffset + (3 * i) + 1] = (uint8_t)((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
			R[ROffset + (3 * i) + 2] = (uint8_t)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
		}
	}
	else if (Eta == 4)
	{
		for (size_t i = 0; i < A.size() / 2; ++i)
		{
			t[0] = (uint8_t)(Eta - A[2 * i]);
			t[1] = (uint8_t)(Eta - A[(2 * i) + 1]);
			R[ROffset + i] = (uint8_t)(t[0] | (t[1] << 4));
		}
	}
}

void DLTMPolyMath::PolyEtaUnpack(std::array<int32_t, 256> &R, const std::vector<uint8_t> &A, size_t AOffset, uint32_t Eta)
{
	if (Eta == 2)
	{
		for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
		{
			R[8 * i] = (A[AOffset + (3 * i)] >> 0) & 7;
			R[(8 * i) + 1] = (A[AOffset + (3 * i)] >> 3) & 7;
			R[(8 * i) + 2] = ((A[AOffset + 3 * i] >> 6) | (A[AOffset + (3 * i) + 1] << 2)) & 7;
			R[(8 * i) + 3] = (A[AOffset + (3 * i) + 1] >> 1) & 7;
			R[(8 * i) + 4] = (A[AOffset + (3 * i) + 1] >> 4) & 7;
			R[(8 * i) + 5] = ((A[AOffset + (3 * i) + 1] >> 7) | (A[AOffset + (3 * i) + 2] << 1)) & 7;
			R[(8 * i) + 6] = (A[AOffset + (3 * i) + 2] >> 2) & 7;
			R[(8 * i) + 7] = (A[AOffset + (3 * i) + 2] >> 5) & 7;

			R[8 * i] = Eta - R[8 * i];
			R[(8 * i) + 1] = Eta - R[(8 * i) + 1];
			R[(8 * i) + 2] = Eta - R[(8 * i) + 2];
			R[(8 * i) + 3] = Eta - R[(8 * i) + 3];
			R[(8 * i) + 4] = Eta - R[(8 * i) + 4];
			R[(8 * i) + 5] = Eta - R[(8 * i) + 5];
			R[(8 * i) + 6] = Eta - R[(8 * i) + 6];
			R[(8 * i) + 7] = Eta - R[(8 * i) + 7];
		}
	}
	else if (Eta == 4)
	{
		for (size_t i = 0; i < DILITHIUM_N / 2; ++i)
		{
			R[2 * i] = A[AOffset + i] & 0x0F;
			R[(2 * i) + 1] = A[AOffset + i] >> 4;
			R[2 * i] = Eta - R[2 * i];
			R[(2 * i) + 1] = Eta - R[(2 * i) + 1];
		}
	}
}

void DLTMPolyMath::PolyInvNttMont(std::array<int32_t, 256> &A)
{
	InvNttToMont(A);
}

void DLTMPolyMath::PolyNtt(std::array<int32_t, 256> &A)
{
	Ntt(A);
}

void DLTMPolyMath::PolyPointwiseInvMont(std::array<int32_t, 256> &C, const std::array<int32_t, 256> &A, const std::array<int32_t, 256> &B)
{
	size_t i;

	for (i = 0; i < C.size(); ++i)
	{
		C[i] = MontReduce(static_cast<uint64_t>(A[i]) * B[i]);
	}
}

void DLTMPolyMath::PolyPointwiseMont(std::array<int32_t, 256> &C, const std::array<int32_t, 256> &A, const std::array<int32_t, 256> &B)
{
    for (size_t i = 0; i < C.size(); ++i)
    {
        C[i] = MontReduce(static_cast<int64_t>(A[i]) * B[i]);
    }
}

void DLTMPolyMath::PolyT0Pack(std::vector<uint8_t> &R, size_t ROffset, const std::array<int32_t, 256> &A)
{
	std::array<int32_t, 8> t;

    for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        t[0] = (1 << (DILITHIUM_D - 1)) - A[8 * i];
        t[1] = (1 << (DILITHIUM_D - 1)) - A[(8 * i) + 1];
        t[2] = (1 << (DILITHIUM_D - 1)) - A[(8 * i) + 2];
        t[3] = (1 << (DILITHIUM_D - 1)) - A[(8 * i) + 3];
        t[4] = (1 << (DILITHIUM_D - 1)) - A[(8 * i) + 4];
        t[5] = (1 << (DILITHIUM_D - 1)) - A[(8 * i) + 5];
        t[6] = (1 << (DILITHIUM_D - 1)) - A[(8 * i) + 6];
        t[7] = (1 << (DILITHIUM_D - 1)) - A[(8 * i) + 7];

        R[ROffset + (13 * i)] = (uint8_t)t[0];
        R[ROffset + (13 * i) + 1] = (uint8_t)(t[0] >> 8);
        R[ROffset + (13 * i) + 1] |= (uint8_t)(t[1] << 5);
        R[ROffset + (13 * i) + 2] = (uint8_t)(t[1] >> 3);
        R[ROffset + (13 * i) + 3] = (uint8_t)(t[1] >> 11);
        R[ROffset + (13 * i) + 3] |= (uint8_t)(t[2] << 2);
        R[ROffset + (13 * i) + 4] = (uint8_t)(t[2] >> 6);
        R[ROffset + (13 * i) + 4] |= (uint8_t)(t[3] << 7);
        R[ROffset + (13 * i) + 5] = (uint8_t)(t[3] >> 1);
        R[ROffset + (13 * i) + 6] = (uint8_t)(t[3] >> 9);
        R[ROffset + (13 * i) + 6] |= (uint8_t)(t[4] << 4);
        R[ROffset + (13 * i) + 7] = (uint8_t)(t[4] >> 4);
        R[ROffset + (13 * i) + 8] = (uint8_t)(t[4] >> 12);
        R[ROffset + (13 * i) + 8] |= (uint8_t)(t[5] << 1);
        R[ROffset + (13 * i) + 9] = (uint8_t)(t[5] >> 7);
        R[ROffset + (13 * i) + 9] |= (uint8_t)(t[6] << 6);
        R[ROffset + (13 * i) + 10] = (uint8_t)(t[6] >> 2);
        R[ROffset + (13 * i) + 11] = (uint8_t)(t[6] >> 10);
        R[ROffset + (13 * i) + 11] |= (uint8_t)(t[7] << 3);
        R[ROffset + (13 * i) + 12] = (uint8_t)(t[7] >> 5);
    }
}

void DLTMPolyMath::PolyT0Unpack(std::array<int32_t, 256> &R, const std::vector<uint8_t> &A, size_t AOffset)
{
	for (size_t i = 0; i < DILITHIUM_N / 8; ++i)
    {
        R[8 * i] = A[AOffset + (13 * i)];
        R[8 * i] |= (uint32_t)A[AOffset + (13 * i) + 1] << 8;
        R[8 * i] &= 0x00001FFFL;

        R[(8 * i) + 1] = A[AOffset + (13 * i) + 1] >> 5;
        R[(8 * i) + 1] |= (uint32_t)A[AOffset + (13 * i) + 2] << 3;
        R[(8 * i) + 1] |= (uint32_t)A[AOffset + (13 * i) + 3] << 11;
        R[(8 * i) + 1] &= 0x00001FFFL;

        R[(8 * i) + 2] = A[AOffset + (13 * i) + 3] >> 2;
        R[(8 * i) + 2] |= (uint32_t)A[AOffset + (13 * i) + 4] << 6;
        R[(8 * i) + 2] &= 0x00001FFFL;

        R[(8 * i) + 3] = A[AOffset + (13 * i) + 4] >> 7;
        R[(8 * i) + 3] |= (uint32_t)A[AOffset + (13 * i) + 5] << 1;
        R[(8 * i) + 3] |= (uint32_t)A[AOffset + (13 * i) + 6] << 9;
        R[(8 * i) + 3] &= 0x00001FFFL;

        R[(8 * i) + 4] = A[AOffset + (13 * i) + 6] >> 4;
        R[(8 * i) + 4] |= (uint32_t)A[AOffset + (13 * i) + 7] << 4;
        R[(8 * i) + 4] |= (uint32_t)A[AOffset + (13 * i) + 8] << 12;
        R[(8 * i) + 4] &= 0x00001FFFL;

        R[(8 * i) + 5] = A[AOffset + (13 * i) + 8] >> 1;
        R[(8 * i) + 5] |= (uint32_t)A[AOffset + (13 * i) + 9] << 7;
        R[(8 * i) + 5] &= 0x00001FFFL;

        R[(8 * i) + 6] = A[AOffset + (13 * i) + 9] >> 6;
        R[(8 * i) + 6] |= (uint32_t)A[AOffset + (13 * i) + 10] << 2;
        R[(8 * i) + 6] |= (uint32_t)A[AOffset + (13 * i) + 11] << 10;
        R[(8 * i) + 6] &= 0x00001FFFL;

        R[(8 * i) + 7] = A[AOffset + (13 * i) + 11] >> 3;
        R[(8 * i) + 7] |= (uint32_t)A[AOffset + (13 * i) + 12] << 5;
        R[(8 * i) + 7] &= 0x00001FFFL;

        R[8 * i] = (1 << (DILITHIUM_D - 1)) - R[8 * i];
        R[(8 * i) + 1] = (1 << (DILITHIUM_D - 1)) - R[(8 * i) + 1];
        R[(8 * i) + 2] = (1 << (DILITHIUM_D - 1)) - R[(8 * i) + 2];
        R[(8 * i) + 3] = (1 << (DILITHIUM_D - 1)) - R[(8 * i) + 3];
        R[(8 * i) + 4] = (1 << (DILITHIUM_D - 1)) - R[(8 * i) + 4];
        R[(8 * i) + 5] = (1 << (DILITHIUM_D - 1)) - R[(8 * i) + 5];
        R[(8 * i) + 6] = (1 << (DILITHIUM_D - 1)) - R[(8 * i) + 6];
        R[(8 * i) + 7] = (1 << (DILITHIUM_D - 1)) - R[(8 * i) + 7];
    }
}

void DLTMPolyMath::PolyT1Pack(std::vector<uint8_t> &R, size_t ROffset, const std::array<int32_t, 256> &A)
{
	for (size_t i = 0; i < A.size() / 4; ++i)
    {
        R[ROffset + (5 * i)] = (uint8_t)(A[4 * i] >> 0);
        R[ROffset + (5 * i) + 1] = (uint8_t)((A[4 * i] >> 8) | (A[(4 * i) + 1] << 2));
        R[ROffset + (5 * i) + 2] = (uint8_t)((A[(4 * i) + 1] >> 6) | (A[(4 * i) + 2] << 4));
        R[ROffset + (5 * i) + 3] = (uint8_t)((A[(4 * i) + 2] >> 4) | (A[(4 * i) + 3] << 6));
        R[ROffset + (5 * i) + 4] = (uint8_t)(A[(4 * i) + 3] >> 2);
    }
}

void DLTMPolyMath::PolyT1Unpack(std::array<int32_t, 256> &R, const std::vector<uint8_t> &A, size_t AOffset)
{
	for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
    {
        R[4 * i] = ((A[AOffset + (5 * i)] >> 0) | ((uint32_t)A[AOffset + (5 * i) + 1] << 8)) & 0x000003FF;
        R[(4 * i) + 1] = ((A[AOffset + (5 * i) + 1] >> 2) | ((uint32_t)A[AOffset + (5 * i) + 2] << 6)) & 0x000003FF;
        R[(4 * i) + 2] = ((A[AOffset + (5 * i) + 2] >> 4) | ((uint32_t)A[AOffset + (5 * i) + 3] << 4)) & 0x000003FF;
        R[(4 * i) + 3] = ((A[AOffset + (5 * i) + 3] >> 6) | ((uint32_t)A[AOffset + (5 * i) + 4] << 2)) & 0x000003FF;
    }
}

void DLTMPolyMath::PolyUniform(std::array<int32_t, 256> &A, const std::vector<uint8_t> &Seed, uint16_t Nonce)
{
	const size_t NBLKS = (769 + Keccak::KECCAK128_RATE_SIZE) / Keccak::KECCAK128_RATE_SIZE;
	std::vector<uint8_t> buf((NBLKS * Keccak::KECCAK128_RATE_SIZE) + 2);
	std::array<uint64_t, Keccak::KECCAK_STATE_SIZE> state = { 0 };
	std::vector<uint8_t> tmps(Seed.size() + 2);
	size_t buflen;
	size_t ctr;
	size_t i;
	size_t off;

	buflen = NBLKS * Keccak::KECCAK128_RATE_SIZE;

	MemoryTools::Copy(Seed, 0, tmps, 0, Seed.size());
	tmps[Seed.size()] = static_cast<uint8_t>(Nonce);
	tmps[Seed.size() + 1] = Nonce >> 8;

	Keccak::Absorb(tmps, 0, tmps.size(), Keccak::KECCAK128_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, state);
	Keccak::Squeeze(state, buf, 0, NBLKS, Keccak::KECCAK128_RATE_SIZE);

	ctr = RejUniform(A, 0, A.size(), buf, buflen);

	while (ctr < DILITHIUM_N)
	{
		off = buflen % 3;

		for (i = 0; i < off; ++i)
		{
			buf[i] = buf[buflen - off + i];
		}

		buflen = Keccak::KECCAK128_RATE_SIZE + off;
		Keccak::Squeeze(state, buf, off, 1, Keccak::KECCAK128_RATE_SIZE);
		ctr += RejUniform(A, ctr, A.size() - ctr, buf, buflen);
	}
}

void DLTMPolyMath::PolyUniformEta(std::array<int32_t, 256> &A, const std::vector<uint8_t> &Seed, uint16_t Nonce, uint32_t Eta, uint32_t Blocks)
{
	std::vector<uint8_t> buf(Blocks * Keccak::KECCAK128_RATE_SIZE);
	std::array<uint64_t, Keccak::KECCAK_STATE_SIZE> state = { 0 };
	std::vector<uint8_t> tmps(Seed.size() + 2);
	size_t ctr;
	size_t buflen;

	MemoryTools::Copy(Seed, 0, tmps, 0, Seed.size());
	tmps[Seed.size()] = static_cast<uint8_t>(Nonce);
	tmps[Seed.size() + 1] = Nonce >> 8;

	buflen = Blocks * Keccak::KECCAK128_RATE_SIZE;
	Keccak::Absorb(tmps, 0, tmps.size(), Keccak::KECCAK128_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, state);
	Keccak::Squeeze(state, buf, 0, Blocks, Keccak::KECCAK128_RATE_SIZE);

	ctr = RejEta(A, 0, A.size(), buf, buflen, Eta);

	while (ctr < DILITHIUM_N)
	{
		Keccak::Squeeze(state, buf, 0, 1, Keccak::KECCAK128_RATE_SIZE);
		ctr += RejEta(A, ctr, A.size() - ctr, buf, Keccak::KECCAK128_RATE_SIZE, Eta);
	}
}

void DLTMPolyMath::PolyZPack(std::vector<uint8_t> &R, size_t ROffset, const std::array<int32_t, 256> &A, uint32_t Gamma1)
{
	std::array<uint32_t, 4> t = { 0 };

	if (Gamma1 == (1 << 17))
	{
		for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
		{
			t[0] = Gamma1 - A[4 * i];
			t[1] = Gamma1 - A[(4 * i) + 1];
			t[2] = Gamma1 - A[(4 * i) + 2];
			t[3] = Gamma1 - A[(4 * i) + 3];

			R[ROffset + (9 * i)] = (uint8_t)t[0];
			R[ROffset + (9 * i) + 1] = (uint8_t)(t[0] >> 8);
			R[ROffset + (9 * i) + 2] = (uint8_t)(t[0] >> 16);
			R[ROffset + (9 * i) + 2] |= (uint8_t)(t[1] << 2);
			R[ROffset + (9 * i) + 3] = (uint8_t)(t[1] >> 6);
			R[ROffset + (9 * i) + 4] = (uint8_t)(t[1] >> 14);
			R[ROffset + (9 * i) + 4] |= (uint8_t)(t[2] << 4);
			R[ROffset + (9 * i) + 5] = (uint8_t)(t[2] >> 4);
			R[ROffset + (9 * i) + 6] = (uint8_t)(t[2] >> 12);
			R[ROffset + (9 * i) + 6] |= (uint8_t)(t[3] << 6);
			R[ROffset + (9 * i) + 7] = (uint8_t)(t[3] >> 2);
			R[ROffset + (9 * i) + 8] = (uint8_t)(t[3] >> 10);
		}
	}
	else if (Gamma1 == (1 << 19))
	{
		for (size_t i = 0; i < DILITHIUM_N / 2; ++i)
		{
			t[0] = Gamma1 - A[2 * i];
			t[1] = Gamma1 - A[(2 * i) + 1];

			R[ROffset + (5 * i)] = (uint8_t)t[0];
			R[ROffset + (5 * i) + 1] = (uint8_t)(t[0] >> 8);
			R[ROffset + (5 * i) + 2] = (uint8_t)(t[0] >> 16);
			R[ROffset + (5 * i) + 2] |= (uint8_t)(t[1] << 4);
			R[ROffset + (5 * i) + 3] = (uint8_t)(t[1] >> 4);
			R[ROffset + (5 * i) + 4] = (uint8_t)(t[1] >> 12);
		}
	}
}

void DLTMPolyMath::PolyZUnpack(std::array<int32_t, 256> &R, const std::vector<uint8_t> &A, size_t AOffset, uint32_t Gamma1)
{
	if (Gamma1 == (1 << 17))
	{
		for (size_t i = 0; i < DILITHIUM_N / 4; ++i)
		{
			R[4 * i] = A[AOffset + 9 * i];
			R[4 * i] |= (uint32_t)A[AOffset + (9 * i) + 1] << 8;
			R[4 * i] |= (uint32_t)A[AOffset + (9 * i) + 2] << 16;
			R[4 * i] &= 0x0003FFFF;

			R[(4 * i) + 1] = A[AOffset + (9 * i) + 2] >> 2;
			R[(4 * i) + 1] |= (uint32_t)A[AOffset + (9 * i) + 3] << 6;
			R[(4 * i) + 1] |= (uint32_t)A[AOffset + (9 * i) + 4] << 14;
			R[(4 * i) + 1] &= 0x0003FFFF;

			R[(4 * i) + 2] = A[AOffset + (9 * i) + 4] >> 4;
			R[(4 * i) + 2] |= (uint32_t)A[AOffset + (9 * i) + 5] << 4;
			R[(4 * i) + 2] |= (uint32_t)A[AOffset + (9 * i) + 6] << 12;
			R[(4 * i) + 2] &= 0x0003FFFF;

			R[(4 * i) + 3] = A[AOffset + (9 * i) + 6] >> 6;
			R[(4 * i) + 3] |= (uint32_t)A[AOffset + (9 * i) + 7] << 2;
			R[(4 * i) + 3] |= (uint32_t)A[AOffset + (9 * i) + 8] << 10;
			R[(4 * i) + 3] &= 0x0003FFFF;

			R[4 * i] = Gamma1 - R[4 * i];
			R[(4 * i) + 1] = Gamma1 - R[(4 * i) + 1];
			R[(4 * i) + 2] = Gamma1 - R[(4 * i) + 2];
			R[(4 * i) + 3] = Gamma1 - R[(4 * i) + 3];
		}
	}
	else if (Gamma1 == (1 << 19))
	{
		for (size_t i = 0; i < DILITHIUM_N / 2; ++i)
		{
			R[2 * i] = A[AOffset + 5 * i];
			R[2 * i] |= (uint32_t)A[AOffset + (5 * i) + 1] << 8;
			R[2 * i] |= (uint32_t)A[AOffset + (5 * i) + 2] << 16;
			R[2 * i] &= 0x000FFFFFL;

			R[(2 * i) + 1] = A[AOffset + (5 * i) + 2] >> 4;
			R[(2 * i) + 1] |= (uint32_t)A[AOffset + (5 * i) + 3] << 4;
			R[(2 * i) + 1] |= (uint32_t)A[AOffset + (5 * i) + 4] << 12;
			R[2 * i] &= 0x000FFFFFL;

			R[2 * i] = Gamma1 - R[2 * i];
			R[(2 * i) + 1] = Gamma1 - R[(2 * i) + 1];
		}
	}
}

void DLTMPolyMath::PolyUniformGamma1M1(std::array<int32_t, 256> &A, const std::vector<uint8_t> &Seed, uint16_t Nonce, uint32_t Gamma1)
{
	const size_t NBLKS = (641 + Keccak::KECCAK256_RATE_SIZE) / Keccak::KECCAK256_RATE_SIZE;
	std::vector<uint8_t> buf((NBLKS * Keccak::KECCAK256_RATE_SIZE) + 4);
	std::array<uint64_t, Keccak::KECCAK_STATE_SIZE> kctx = { 0 };
	std::vector<uint8_t> tmps(Seed.size() + 2);

	MemoryTools::Copy(Seed, 0, tmps, 0, Seed.size());
	tmps[Seed.size()] = static_cast<uint8_t>(Nonce);
	tmps[Seed.size() + 1] = Nonce >> 8;
	Keccak::Absorb(tmps, 0, tmps.size(), Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx);
	Keccak::Squeeze(kctx, buf, 0, NBLKS, Keccak::KECCAK256_RATE_SIZE);

	PolyZUnpack(A, buf, 0, Gamma1);
}

size_t DLTMPolyMath::RejEta(std::array<int32_t, 256> &A, size_t AOffset, size_t ALength, const std::vector<uint8_t> &Buffer, size_t BufLength, uint32_t Eta)
{
	size_t ctr;
	size_t pos;
	uint32_t t0;
	uint32_t t1;

	ctr = pos = 0;

	while (ctr < ALength && pos < BufLength)
	{
		t0 = Buffer[pos] & 0x0F;
		t1 = Buffer[pos] >> 4;
		++pos;

		if (Eta == 2)
		{
			if (t0 < 15)
			{
				t0 = t0 - (205 * t0 >> 10) * 5;
				A[ctr] = 2 - t0;
				++ctr;
			}

			if (t1 < 15 && ctr < ALength)
			{
				t1 = t1 - (205 * t1 >> 10) * 5;
				A[ctr] = 2 - t1;
				++ctr;
			}
		}
		else if (Eta == 4)
		{
			if (t0 < 9)
			{
				A[ctr] = 4 - t0;
				++ctr;
			}

			if (t1 < 9 && ctr < ALength)
			{
				A[ctr] = 4 - t1;
				++ctr;
			}
		}
	}

	return ctr;
}

size_t DLTMPolyMath::RejUniform(std::array<int32_t, 256> &A, size_t AOffset, size_t ALength, const std::vector<uint8_t> &Buffer, size_t BufLength)
{
	size_t ctr;
	size_t pos;
	uint32_t t;

	ctr = 0;
	pos = 0;

	while (ctr < ALength && pos + 3 <= BufLength)
	{
		t = Buffer[pos];
		++pos;
		t |= static_cast<uint32_t>(Buffer[pos]) << 8;
		++pos;
		t |= static_cast<uint32_t>(Buffer[pos]) << 16;
		++pos;
		t &= 0x007FFFFFUL;

		if (t < DILITHIUM_Q)
		{
			A[AOffset + ctr] = t;
			++ctr;
		}
	}

	return ctr;
}

// polyvec.c //

void DLTMPolyMath::PolyVecAdd(std::vector<std::array<int32_t, 256>> &W, const std::vector<std::array<int32_t, 256>> &U, const std::vector<std::array<int32_t, 256>> &V)
{
	size_t i;

	for (i = 0; i < W.size(); ++i)
	{
		PolyAdd(W[i], U[i], V[i]);
	}
}

int32_t DLTMPolyMath::PolyVecChkNorm(const std::vector<std::array<int32_t, 256>> &V, uint32_t bound)
{
	size_t i;
	int32_t r;

	r = 0;

	for (i = 0; i < V.size(); ++i)
	{
		if (PolyChkNorm(V[i], bound))
		{
			r = 1;
			break;
		}
	}

	return r;
}

void DLTMPolyMath::PolyVecDecompose(std::vector<std::array<int32_t, 256>> &V1, std::vector<std::array<int32_t, 256>> &V0, const std::vector<std::array<int32_t, 256>> &V, uint32_t Gamma2)
{
	size_t i;

	for (i = 0; i < V1.size(); ++i)
	{
		PolyDecompose(V1[i], V0[i], V[i], Gamma2);
	}
}

void DLTMPolyMath::PolyVecCaddQ(std::vector<std::array<int32_t, 256>> &V)
{
    for (size_t i = 0; i < V.size(); ++i)
    {
        PolyCaddQ(V[i]);
    }
}

void DLTMPolyMath::PolyVecInvNttMont(std::vector<std::array<int32_t, 256>> &V)
{
		for (size_t i = 0; i < V.size(); ++i)
	{
		DLTMPolyMath::PolyInvNttMont(V[i]);
	}
}

void DLTMPolyMath::PolyVecMatrixPointwiseMont(std::array<int32_t, 256> &W, const std::vector<std::array<int32_t, 256>> &U, const std::vector<std::array<int32_t, 256>> &V)
{
	std::array<int32_t, 256> t;
	size_t i;

	PolyPointwiseInvMont(W, U[0], V[0]);

	for (i = 1; i < U.size(); ++i)
	{
		PolyPointwiseInvMont(t, U[i], V[i]);
		PolyAdd(W, W, t);
	}
}

void DLTMPolyMath::PolyVecNtt(std::vector<std::array<int32_t, 256>> &V)
{
	size_t i;

	for (i = 0; i < V.size(); ++i)
	{
		PolyNtt(V[i]);
	}
}

void DLTMPolyMath::PolyVecPointwiseInvMont(std::vector<std::array<int32_t, 256>> &C, const std::array<int32_t, 256> &A, const std::vector<std::array<int32_t, 256>> &B)
{
	for (size_t i = 0; i < C.size(); ++i)
	{
		PolyPointwiseInvMont(C[i], A, B[i]);
	}
}

uint32_t DLTMPolyMath::PolyVecMakeHint(std::vector<std::array<int32_t, 256>> &H, const std::vector<std::array<int32_t, 256>> &A0, const std::vector<std::array<int32_t, 256>> &A1, uint32_t Gamma2)
{
	uint32_t n;

	n = 0;

	for (size_t i = 0; i < H.size(); ++i)
	{
		n += PolyMakeHint(H[i], A0[i], A1[i], Gamma2);
	}

	return n;
}

void DLTMPolyMath::PolyVecPointwiseMont(std::vector<std::array<int32_t, 256>> &C, const std::array<int32_t, 256> &A, const std::vector<std::array<int32_t, 256>> &B)
{
	for (size_t i = 0; i < C.size(); ++i)
	{
		PolyPointwiseMont(C[i], A, B[i]);
	}
}

void DLTMPolyMath::PolyVecPower2Round(std::vector<std::array<int32_t, 256>> &V1, std::vector<std::array<int32_t, 256>> &V0, const std::vector<std::array<int32_t, 256>> &V)
{
	size_t i;

	for (i = 0; i < V1.size(); ++i)
	{
		PolyPower2Round(V1[i], V0[i], V[i]);
	}
}

void DLTMPolyMath::PolyVecReduce(std::vector<std::array<int32_t, 256>> &V)
{
	for (size_t i = 0; i < V.size(); ++i)
	{
		DLTMPolyMath::PolyReduce(V[i]);
	}
}

void DLTMPolyMath::PolyVecShiftL(std::vector<std::array<int32_t, 256>> &V)
{
	size_t i;

	for (i = 0; i < V.size(); ++i)
	{
		PolyShiftL(V[i]);
	}
}

void DLTMPolyMath::PolyVecSub(std::vector<std::array<int32_t, 256>> &C, const std::vector<std::array<int32_t, 256>> &A, const std::vector<std::array<int32_t, 256>> &B)
{
	for (size_t i = 0; i < C.size(); ++i)
	{
		PolySub(C[i], A[i], B[i]);
	}
}

void DLTMPolyMath::PolyVecUniformGamma1M1(std::vector<std::array<int32_t, 256>> &V, const std::vector<uint8_t> &Seed, uint16_t nonce, uint32_t Gamma1)
{
    for (size_t i = 0; i < V.size(); ++i)
    {
        PolyUniformGamma1M1(V[i], Seed, (uint16_t)((V.size() * nonce) + i), Gamma1);
    }
}

void DLTMPolyMath::PolyVecUseHint(std::vector<std::array<int32_t, 256>> &B, const std::vector<std::array<int32_t, 256>> &A, const std::vector<std::array<int32_t, 256>> &H, uint32_t Gamma2)
{
	for (size_t i = 0; i < B.size(); ++i)
	{
		PolyUseHint(B[i], A[i], H[i], Gamma2);
	}
}

// reduce.c //

int32_t DLTMPolyMath::CaddQ(int32_t a)
{
    a += (a >> 31) & DILITHIUM_Q;

    return a;
}

int32_t DLTMPolyMath::MontReduce(int64_t A)
{
	int32_t t;

	t = (int32_t)A * DILITHIUM_QINV;
	t = (A - (int64_t)t * DILITHIUM_Q) >> 32;

	return t;
}

int32_t DLTMPolyMath::Reduce32(int32_t A)
{
	int32_t t;

	t = (A + (1 << 22)) >> 23;
	t = A - t * DILITHIUM_Q;

	return t;
}

// rounding.c //

int32_t DLTMPolyMath::Decompose(int32_t &A0, int32_t A, uint32_t Gamma2)
{
    int32_t a1;

    a1 = (A + 127) >> 7;

	if (Gamma2 == (DILITHIUM_Q - 1) / 32)
	{
		a1 = ((a1 * 1025) + (1 << 21)) >> 22;
		a1 &= 15;
	}
	else if (Gamma2 == (DILITHIUM_Q - 1) / 88)
	{
		a1 = ((a1 * 11275) + (1 << 23)) >> 24;
		a1 ^= ((43 - a1) >> 31) & a1;
	}

    A0 = A - (a1 * 2 * Gamma2);
    A0 -= ((((DILITHIUM_Q - 1) / 2) - A0) >> 31) & DILITHIUM_Q;

    return a1;
}

int32_t DLTMPolyMath::MakeHint(int32_t A0, int32_t A1, int32_t Gamma2)
{
    uint32_t res;

    res = 1;

    if (A0 <= Gamma2 || A0 > DILITHIUM_Q - Gamma2 || (A0 == DILITHIUM_Q - Gamma2 && A1 == 0))
    {
        res = 0;
    }

    return res;
}

int32_t DLTMPolyMath::Power2Round(int32_t A, int32_t &A0)
{
    int32_t a1;

    a1 = (A + (1 << (DILITHIUM_D - 1)) - 1) >> DILITHIUM_D;
    A0 = A - (a1 << DILITHIUM_D);

    return a1;
}

uint32_t DLTMPolyMath::UseHint(int32_t A, const int32_t Hint, uint32_t Gamma2)
{
    int32_t a0;
    int32_t a1;
    int32_t res;

	a0 = 0;
	res = 0;
    a1 = Decompose(a0, A, Gamma2);

    if (Hint == 0)
    {
        res = a1;
    }
    else
    {
		if (Gamma2 == (DILITHIUM_Q - 1) / 32)
		{
			if (a0 > 0)
			{
				res = (a1 + 1) & 15;
			}
			else
			{
				res = (a1 - 1) & 15;
			}
		}
		else if (Gamma2 == (DILITHIUM_Q - 1) / 88)
		{
			if (a0 > 0)
			{
				res = (a1 == 43) ? 0 : a1 + 1;
			}
			else
			{
				res = (a1 == 0) ? 43 : a1 - 1;
			}
		}
    }

    return res;
}

// sign.c //

void DLTMPolyMath::ExpandMat(std::vector<std::vector<std::array<int32_t, 256>>> &Matrix, const std::vector<uint8_t> &Rho)
{
	size_t i;
	size_t j;

	for (i = 0; i < Matrix.size(); ++i)
	{
		for (j = 0; j < Matrix[i].size(); ++j)
		{
			PolyUniform(Matrix[i][j], Rho, static_cast<uint16_t>(((i << 8) + j)));
		}
	}
}

NAMESPACE_DILITHIUMEND
