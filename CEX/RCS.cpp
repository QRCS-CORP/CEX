#include "RCS.h"
#include "CpuDetect.h"
#include "IntegerTools.h"
#include "MacFromName.h"
#include "MemoryTools.h"
#include "Rijndael.h"
#include "SHAKE.h"

NAMESPACE_STREAM

using namespace Cipher::Block::RijndaelBase;
using Utility::IntegerTools;
using Utility::MemoryTools;
using Enumeration::ShakeModes;
using Enumeration::StreamCipherConvert;

const std::vector<byte> RCS::OMEGA_INFO = 
{
	0x52, 0x43, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x31, 0x2E, 0x30, 0x63
};

const std::vector<uint> RCS::MT0 =
{
	0xC66363A5UL, 0xF87C7C84UL, 0xEE777799UL, 0xF67B7B8DUL, 0xFFF2F20DUL, 0xD66B6BBDUL, 0xDE6F6FB1UL, 0x91C5C554UL,
	0x60303050UL, 0x02010103UL, 0xCE6767A9UL, 0x562B2B7DUL, 0xE7FEFE19UL, 0xB5D7D762UL, 0x4DABABE6UL, 0xEC76769AUL,
	0x8FCACA45UL, 0x1F82829DUL, 0x89C9C940UL, 0xFA7D7D87UL, 0xEFFAFA15UL, 0xB25959EBUL, 0x8E4747C9UL, 0xFBF0F00BUL,
	0x41ADADECUL, 0xB3D4D467UL, 0x5FA2A2FDUL, 0x45AFAFEAUL, 0x239C9CBFUL, 0x53A4A4F7UL, 0xE4727296UL, 0x9BC0C05BUL,
	0x75B7B7C2UL, 0xE1FDFD1CUL, 0x3D9393AEUL, 0x4C26266AUL, 0x6C36365AUL, 0x7E3F3F41UL, 0xF5F7F702UL, 0x83CCCC4FUL,
	0x6834345CUL, 0x51A5A5F4UL, 0xD1E5E534UL, 0xF9F1F108UL, 0xE2717193UL, 0xABD8D873UL, 0x62313153UL, 0x2A15153FUL,
	0x0804040CUL, 0x95C7C752UL, 0x46232365UL, 0x9DC3C35EUL, 0x30181828UL, 0x379696A1UL, 0x0A05050FUL, 0x2F9A9AB5UL,
	0x0E070709UL, 0x24121236UL, 0x1B80809BUL, 0xDFE2E23DUL, 0xCDEBEB26UL, 0x4E272769UL, 0x7FB2B2CDUL, 0xEA75759FUL,
	0x1209091BUL, 0x1D83839EUL, 0x582C2C74UL, 0x341A1A2EUL, 0x361B1B2DUL, 0xDC6E6EB2UL, 0xB45A5AEEUL, 0x5BA0A0FBUL,
	0xA45252F6UL, 0x763B3B4DUL, 0xB7D6D661UL, 0x7DB3B3CEUL, 0x5229297BUL, 0xDDE3E33EUL, 0x5E2F2F71UL, 0x13848497UL,
	0xA65353F5UL, 0xB9D1D168UL, 0x00000000UL, 0xC1EDED2CUL, 0x40202060UL, 0xE3FCFC1FUL, 0x79B1B1C8UL, 0xB65B5BEDUL,
	0xD46A6ABEUL, 0x8DCBCB46UL, 0x67BEBED9UL, 0x7239394BUL, 0x944A4ADEUL, 0x984C4CD4UL, 0xB05858E8UL, 0x85CFCF4AUL,
	0xBBD0D06BUL, 0xC5EFEF2AUL, 0x4FAAAAE5UL, 0xEDFBFB16UL, 0x864343C5UL, 0x9A4D4DD7UL, 0x66333355UL, 0x11858594UL,
	0x8A4545CFUL, 0xE9F9F910UL, 0x04020206UL, 0xFE7F7F81UL, 0xA05050F0UL, 0x783C3C44UL, 0x259F9FBAUL, 0x4BA8A8E3UL,
	0xA25151F3UL, 0x5DA3A3FEUL, 0x804040C0UL, 0x058F8F8AUL, 0x3F9292ADUL, 0x219D9DBCUL, 0x70383848UL, 0xF1F5F504UL,
	0x63BCBCDFUL, 0x77B6B6C1UL, 0xAFDADA75UL, 0x42212163UL, 0x20101030UL, 0xE5FFFF1AUL, 0xFDF3F30EUL, 0xBFD2D26DUL,
	0x81CDCD4CUL, 0x180C0C14UL, 0x26131335UL, 0xC3ECEC2FUL, 0xBE5F5FE1UL, 0x359797A2UL, 0x884444CCUL, 0x2E171739UL,
	0x93C4C457UL, 0x55A7A7F2UL, 0xFC7E7E82UL, 0x7A3D3D47UL, 0xC86464ACUL, 0xBA5D5DE7UL, 0x3219192BUL, 0xE6737395UL,
	0xC06060A0UL, 0x19818198UL, 0x9E4F4FD1UL, 0xA3DCDC7FUL, 0x44222266UL, 0x542A2A7EUL, 0x3B9090ABUL, 0x0B888883UL,
	0x8C4646CAUL, 0xC7EEEE29UL, 0x6BB8B8D3UL, 0x2814143CUL, 0xA7DEDE79UL, 0xBC5E5EE2UL, 0x160B0B1DUL, 0xADDBDB76UL,
	0xDBE0E03BUL, 0x64323256UL, 0x743A3A4EUL, 0x140A0A1EUL, 0x924949DBUL, 0x0C06060AUL, 0x4824246CUL, 0xB85C5CE4UL,
	0x9FC2C25DUL, 0xBDD3D36EUL, 0x43ACACEFUL, 0xC46262A6UL, 0x399191A8UL, 0x319595A4UL, 0xD3E4E437UL, 0xF279798BUL,
	0xD5E7E732UL, 0x8BC8C843UL, 0x6E373759UL, 0xDA6D6DB7UL, 0x018D8D8CUL, 0xB1D5D564UL, 0x9C4E4ED2UL, 0x49A9A9E0UL,
	0xD86C6CB4UL, 0xAC5656FAUL, 0xF3F4F407UL, 0xCFEAEA25UL, 0xCA6565AFUL, 0xF47A7A8EUL, 0x47AEAEE9UL, 0x10080818UL,
	0x6FBABAD5UL, 0xF0787888UL, 0x4A25256FUL, 0x5C2E2E72UL, 0x381C1C24UL, 0x57A6A6F1UL, 0x73B4B4C7UL, 0x97C6C651UL,
	0xCBE8E823UL, 0xA1DDDD7CUL, 0xE874749CUL, 0x3E1F1F21UL, 0x964B4BDDUL, 0x61BDBDDCUL, 0x0D8B8B86UL, 0x0F8A8A85UL,
	0xE0707090UL, 0x7C3E3E42UL, 0x71B5B5C4UL, 0xCC6666AAUL, 0x904848D8UL, 0x06030305UL, 0xF7F6F601UL, 0x1C0E0E12UL,
	0xC26161A3UL, 0x6A35355FUL, 0xAE5757F9UL, 0x69B9B9D0UL, 0x17868691UL, 0x99C1C158UL, 0x3A1D1D27UL, 0x279E9EB9UL,
	0xD9E1E138UL, 0xEBF8F813UL, 0x2B9898B3UL, 0x22111133UL, 0xD26969BBUL, 0xA9D9D970UL, 0x078E8E89UL, 0x339494A7UL,
	0x2D9B9BB6UL, 0x3C1E1E22UL, 0x15878792UL, 0xC9E9E920UL, 0x87CECE49UL, 0xAA5555FFUL, 0x50282878UL, 0xA5DFDF7AUL,
	0x038C8C8FUL, 0x59A1A1F8UL, 0x09898980UL, 0x1A0D0D17UL, 0x65BFBFDAUL, 0xD7E6E631UL, 0x844242C6UL, 0xD06868B8UL,
	0x824141C3UL, 0x299999B0UL, 0x5A2D2D77UL, 0x1E0F0F11UL, 0x7BB0B0CBUL, 0xA85454FCUL, 0x6DBBBBD6UL, 0x2C16163AUL
};

const std::vector<uint> RCS::MT1 =
{
	0xA5C66363UL, 0x84F87C7CUL, 0x99EE7777UL, 0x8DF67B7BUL, 0x0DFFF2F2UL, 0xBDD66B6BUL, 0xB1DE6F6FUL, 0x5491C5C5UL,
	0x50603030UL, 0x03020101UL, 0xA9CE6767UL, 0x7D562B2BUL, 0x19E7FEFEUL, 0x62B5D7D7UL, 0xE64DABABUL, 0x9AEC7676UL,
	0x458FCACAUL, 0x9D1F8282UL, 0x4089C9C9UL, 0x87FA7D7DUL, 0x15EFFAFAUL, 0xEBB25959UL, 0xC98E4747UL, 0x0BFBF0F0UL,
	0xEC41ADADUL, 0x67B3D4D4UL, 0xFD5FA2A2UL, 0xEA45AFAFUL, 0xBF239C9CUL, 0xF753A4A4UL, 0x96E47272UL, 0x5B9BC0C0UL,
	0xC275B7B7UL, 0x1CE1FDFDUL, 0xAE3D9393UL, 0x6A4C2626UL, 0x5A6C3636UL, 0x417E3F3FUL, 0x02F5F7F7UL, 0x4F83CCCCUL,
	0x5C683434UL, 0xF451A5A5UL, 0x34D1E5E5UL, 0x08F9F1F1UL, 0x93E27171UL, 0x73ABD8D8UL, 0x53623131UL, 0x3F2A1515UL,
	0x0C080404UL, 0x5295C7C7UL, 0x65462323UL, 0x5E9DC3C3UL, 0x28301818UL, 0xA1379696UL, 0x0F0A0505UL, 0xB52F9A9AUL,
	0x090E0707UL, 0x36241212UL, 0x9B1B8080UL, 0x3DDFE2E2UL, 0x26CDEBEBUL, 0x694E2727UL, 0xCD7FB2B2UL, 0x9FEA7575UL,
	0x1B120909UL, 0x9E1D8383UL, 0x74582C2CUL, 0x2E341A1AUL, 0x2D361B1BUL, 0xB2DC6E6EUL, 0xEEB45A5AUL, 0xFB5BA0A0UL,
	0xF6A45252UL, 0x4D763B3BUL, 0x61B7D6D6UL, 0xCE7DB3B3UL, 0x7B522929UL, 0x3EDDE3E3UL, 0x715E2F2FUL, 0x97138484UL,
	0xF5A65353UL, 0x68B9D1D1UL, 0x00000000UL, 0x2CC1EDEDUL, 0x60402020UL, 0x1FE3FCFCUL, 0xC879B1B1UL, 0xEDB65B5BUL,
	0xBED46A6AUL, 0x468DCBCBUL, 0xD967BEBEUL, 0x4B723939UL, 0xDE944A4AUL, 0xD4984C4CUL, 0xE8B05858UL, 0x4A85CFCFUL,
	0x6BBBD0D0UL, 0x2AC5EFEFUL, 0xE54FAAAAUL, 0x16EDFBFBUL, 0xC5864343UL, 0xD79A4D4DUL, 0x55663333UL, 0x94118585UL,
	0xCF8A4545UL, 0x10E9F9F9UL, 0x06040202UL, 0x81FE7F7FUL, 0xF0A05050UL, 0x44783C3CUL, 0xBA259F9FUL, 0xE34BA8A8UL,
	0xF3A25151UL, 0xFE5DA3A3UL, 0xC0804040UL, 0x8A058F8FUL, 0xAD3F9292UL, 0xBC219D9DUL, 0x48703838UL, 0x04F1F5F5UL,
	0xDF63BCBCUL, 0xC177B6B6UL, 0x75AFDADAUL, 0x63422121UL, 0x30201010UL, 0x1AE5FFFFUL, 0x0EFDF3F3UL, 0x6DBFD2D2UL,
	0x4C81CDCDUL, 0x14180C0CUL, 0x35261313UL, 0x2FC3ECECUL, 0xE1BE5F5FUL, 0xA2359797UL, 0xCC884444UL, 0x392E1717UL,
	0x5793C4C4UL, 0xF255A7A7UL, 0x82FC7E7EUL, 0x477A3D3DUL, 0xACC86464UL, 0xE7BA5D5DUL, 0x2B321919UL, 0x95E67373UL,
	0xA0C06060UL, 0x98198181UL, 0xD19E4F4FUL, 0x7FA3DCDCUL, 0x66442222UL, 0x7E542A2AUL, 0xAB3B9090UL, 0x830B8888UL,
	0xCA8C4646UL, 0x29C7EEEEUL, 0xD36BB8B8UL, 0x3C281414UL, 0x79A7DEDEUL, 0xE2BC5E5EUL, 0x1D160B0BUL, 0x76ADDBDBUL,
	0x3BDBE0E0UL, 0x56643232UL, 0x4E743A3AUL, 0x1E140A0AUL, 0xDB924949UL, 0x0A0C0606UL, 0x6C482424UL, 0xE4B85C5CUL,
	0x5D9FC2C2UL, 0x6EBDD3D3UL, 0xEF43ACACUL, 0xA6C46262UL, 0xA8399191UL, 0xA4319595UL, 0x37D3E4E4UL, 0x8BF27979UL,
	0x32D5E7E7UL, 0x438BC8C8UL, 0x596E3737UL, 0xB7DA6D6DUL, 0x8C018D8DUL, 0x64B1D5D5UL, 0xD29C4E4EUL, 0xE049A9A9UL,
	0xB4D86C6CUL, 0xFAAC5656UL, 0x07F3F4F4UL, 0x25CFEAEAUL, 0xAFCA6565UL, 0x8EF47A7AUL, 0xE947AEAEUL, 0x18100808UL,
	0xD56FBABAUL, 0x88F07878UL, 0x6F4A2525UL, 0x725C2E2EUL, 0x24381C1CUL, 0xF157A6A6UL, 0xC773B4B4UL, 0x5197C6C6UL,
	0x23CBE8E8UL, 0x7CA1DDDDUL, 0x9CE87474UL, 0x213E1F1FUL, 0xDD964B4BUL, 0xDC61BDBDUL, 0x860D8B8BUL, 0x850F8A8AUL,
	0x90E07070UL, 0x427C3E3EUL, 0xC471B5B5UL, 0xAACC6666UL, 0xD8904848UL, 0x05060303UL, 0x01F7F6F6UL, 0x121C0E0EUL,
	0xA3C26161UL, 0x5F6A3535UL, 0xF9AE5757UL, 0xD069B9B9UL, 0x91178686UL, 0x5899C1C1UL, 0x273A1D1DUL, 0xB9279E9EUL,
	0x38D9E1E1UL, 0x13EBF8F8UL, 0xB32B9898UL, 0x33221111UL, 0xBBD26969UL, 0x70A9D9D9UL, 0x89078E8EUL, 0xA7339494UL,
	0xB62D9B9BUL, 0x223C1E1EUL, 0x92158787UL, 0x20C9E9E9UL, 0x4987CECEUL, 0xFFAA5555UL, 0x78502828UL, 0x7AA5DFDFUL,
	0x8F038C8CUL, 0xF859A1A1UL, 0x80098989UL, 0x171A0D0DUL, 0xDA65BFBFUL, 0x31D7E6E6UL, 0xC6844242UL, 0xB8D06868UL,
	0xC3824141UL, 0xB0299999UL, 0x775A2D2DUL, 0x111E0F0FUL, 0xCB7BB0B0UL, 0xFCA85454UL, 0xD66DBBBBUL, 0x3A2C1616UL
};

const std::vector<uint> RCS::MT2 =
{
	0x63A5C663UL, 0x7C84F87CUL, 0x7799EE77UL, 0x7B8DF67BUL, 0xF20DFFF2UL, 0x6BBDD66BUL, 0x6FB1DE6FUL, 0xC55491C5UL,
	0x30506030UL, 0x01030201UL, 0x67A9CE67UL, 0x2B7D562BUL, 0xFE19E7FEUL, 0xD762B5D7UL, 0xABE64DABUL, 0x769AEC76UL,
	0xCA458FCAUL, 0x829D1F82UL, 0xC94089C9UL, 0x7D87FA7DUL, 0xFA15EFFAUL, 0x59EBB259UL, 0x47C98E47UL, 0xF00BFBF0UL,
	0xADEC41ADUL, 0xD467B3D4UL, 0xA2FD5FA2UL, 0xAFEA45AFUL, 0x9CBF239CUL, 0xA4F753A4UL, 0x7296E472UL, 0xC05B9BC0UL,
	0xB7C275B7UL, 0xFD1CE1FDUL, 0x93AE3D93UL, 0x266A4C26UL, 0x365A6C36UL, 0x3F417E3FUL, 0xF702F5F7UL, 0xCC4F83CCUL,
	0x345C6834UL, 0xA5F451A5UL, 0xE534D1E5UL, 0xF108F9F1UL, 0x7193E271UL, 0xD873ABD8UL, 0x31536231UL, 0x153F2A15UL,
	0x040C0804UL, 0xC75295C7UL, 0x23654623UL, 0xC35E9DC3UL, 0x18283018UL, 0x96A13796UL, 0x050F0A05UL, 0x9AB52F9AUL,
	0x07090E07UL, 0x12362412UL, 0x809B1B80UL, 0xE23DDFE2UL, 0xEB26CDEBUL, 0x27694E27UL, 0xB2CD7FB2UL, 0x759FEA75UL,
	0x091B1209UL, 0x839E1D83UL, 0x2C74582CUL, 0x1A2E341AUL, 0x1B2D361BUL, 0x6EB2DC6EUL, 0x5AEEB45AUL, 0xA0FB5BA0UL,
	0x52F6A452UL, 0x3B4D763BUL, 0xD661B7D6UL, 0xB3CE7DB3UL, 0x297B5229UL, 0xE33EDDE3UL, 0x2F715E2FUL, 0x84971384UL,
	0x53F5A653UL, 0xD168B9D1UL, 0x00000000UL, 0xED2CC1EDUL, 0x20604020UL, 0xFC1FE3FCUL, 0xB1C879B1UL, 0x5BEDB65BUL,
	0x6ABED46AUL, 0xCB468DCBUL, 0xBED967BEUL, 0x394B7239UL, 0x4ADE944AUL, 0x4CD4984CUL, 0x58E8B058UL, 0xCF4A85CFUL,
	0xD06BBBD0UL, 0xEF2AC5EFUL, 0xAAE54FAAUL, 0xFB16EDFBUL, 0x43C58643UL, 0x4DD79A4DUL, 0x33556633UL, 0x85941185UL,
	0x45CF8A45UL, 0xF910E9F9UL, 0x02060402UL, 0x7F81FE7FUL, 0x50F0A050UL, 0x3C44783CUL, 0x9FBA259FUL, 0xA8E34BA8UL,
	0x51F3A251UL, 0xA3FE5DA3UL, 0x40C08040UL, 0x8F8A058FUL, 0x92AD3F92UL, 0x9DBC219DUL, 0x38487038UL, 0xF504F1F5UL,
	0xBCDF63BCUL, 0xB6C177B6UL, 0xDA75AFDAUL, 0x21634221UL, 0x10302010UL, 0xFF1AE5FFUL, 0xF30EFDF3UL, 0xD26DBFD2UL,
	0xCD4C81CDUL, 0x0C14180CUL, 0x13352613UL, 0xEC2FC3ECUL, 0x5FE1BE5FUL, 0x97A23597UL, 0x44CC8844UL, 0x17392E17UL,
	0xC45793C4UL, 0xA7F255A7UL, 0x7E82FC7EUL, 0x3D477A3DUL, 0x64ACC864UL, 0x5DE7BA5DUL, 0x192B3219UL, 0x7395E673UL,
	0x60A0C060UL, 0x81981981UL, 0x4FD19E4FUL, 0xDC7FA3DCUL, 0x22664422UL, 0x2A7E542AUL, 0x90AB3B90UL, 0x88830B88UL,
	0x46CA8C46UL, 0xEE29C7EEUL, 0xB8D36BB8UL, 0x143C2814UL, 0xDE79A7DEUL, 0x5EE2BC5EUL, 0x0B1D160BUL, 0xDB76ADDBUL,
	0xE03BDBE0UL, 0x32566432UL, 0x3A4E743AUL, 0x0A1E140AUL, 0x49DB9249UL, 0x060A0C06UL, 0x246C4824UL, 0x5CE4B85CUL,
	0xC25D9FC2UL, 0xD36EBDD3UL, 0xACEF43ACUL, 0x62A6C462UL, 0x91A83991UL, 0x95A43195UL, 0xE437D3E4UL, 0x798BF279UL,
	0xE732D5E7UL, 0xC8438BC8UL, 0x37596E37UL, 0x6DB7DA6DUL, 0x8D8C018DUL, 0xD564B1D5UL, 0x4ED29C4EUL, 0xA9E049A9UL,
	0x6CB4D86CUL, 0x56FAAC56UL, 0xF407F3F4UL, 0xEA25CFEAUL, 0x65AFCA65UL, 0x7A8EF47AUL, 0xAEE947AEUL, 0x08181008UL,
	0xBAD56FBAUL, 0x7888F078UL, 0x256F4A25UL, 0x2E725C2EUL, 0x1C24381CUL, 0xA6F157A6UL, 0xB4C773B4UL, 0xC65197C6UL,
	0xE823CBE8UL, 0xDD7CA1DDUL, 0x749CE874UL, 0x1F213E1FUL, 0x4BDD964BUL, 0xBDDC61BDUL, 0x8B860D8BUL, 0x8A850F8AUL,
	0x7090E070UL, 0x3E427C3EUL, 0xB5C471B5UL, 0x66AACC66UL, 0x48D89048UL, 0x03050603UL, 0xF601F7F6UL, 0x0E121C0EUL,
	0x61A3C261UL, 0x355F6A35UL, 0x57F9AE57UL, 0xB9D069B9UL, 0x86911786UL, 0xC15899C1UL, 0x1D273A1DUL, 0x9EB9279EUL,
	0xE138D9E1UL, 0xF813EBF8UL, 0x98B32B98UL, 0x11332211UL, 0x69BBD269UL, 0xD970A9D9UL, 0x8E89078EUL, 0x94A73394UL,
	0x9BB62D9BUL, 0x1E223C1EUL, 0x87921587UL, 0xE920C9E9UL, 0xCE4987CEUL, 0x55FFAA55UL, 0x28785028UL, 0xDF7AA5DFUL,
	0x8C8F038CUL, 0xA1F859A1UL, 0x89800989UL, 0x0D171A0DUL, 0xBFDA65BFUL, 0xE631D7E6UL, 0x42C68442UL, 0x68B8D068UL,
	0x41C38241UL, 0x99B02999UL, 0x2D775A2DUL, 0x0F111E0FUL, 0xB0CB7BB0UL, 0x54FCA854UL, 0xBBD66DBBUL, 0x163A2C16UL
};

const std::vector<uint> RCS::MT3 =
{
	0x6363A5C6UL, 0x7C7C84F8UL, 0x777799EEUL, 0x7B7B8DF6UL, 0xF2F20DFFUL, 0x6B6BBDD6UL, 0x6F6FB1DEUL, 0xC5C55491UL,
	0x30305060UL, 0x01010302UL, 0x6767A9CEUL, 0x2B2B7D56UL, 0xFEFE19E7UL, 0xD7D762B5UL, 0xABABE64DUL, 0x76769AECUL,
	0xCACA458FUL, 0x82829D1FUL, 0xC9C94089UL, 0x7D7D87FAUL, 0xFAFA15EFUL, 0x5959EBB2UL, 0x4747C98EUL, 0xF0F00BFBUL,
	0xADADEC41UL, 0xD4D467B3UL, 0xA2A2FD5FUL, 0xAFAFEA45UL, 0x9C9CBF23UL, 0xA4A4F753UL, 0x727296E4UL, 0xC0C05B9BUL,
	0xB7B7C275UL, 0xFDFD1CE1UL, 0x9393AE3DUL, 0x26266A4CUL, 0x36365A6CUL, 0x3F3F417EUL, 0xF7F702F5UL, 0xCCCC4F83UL,
	0x34345C68UL, 0xA5A5F451UL, 0xE5E534D1UL, 0xF1F108F9UL, 0x717193E2UL, 0xD8D873ABUL, 0x31315362UL, 0x15153F2AUL,
	0x04040C08UL, 0xC7C75295UL, 0x23236546UL, 0xC3C35E9DUL, 0x18182830UL, 0x9696A137UL, 0x05050F0AUL, 0x9A9AB52FUL,
	0x0707090EUL, 0x12123624UL, 0x80809B1BUL, 0xE2E23DDFUL, 0xEBEB26CDUL, 0x2727694EUL, 0xB2B2CD7FUL, 0x75759FEAUL,
	0x09091B12UL, 0x83839E1DUL, 0x2C2C7458UL, 0x1A1A2E34UL, 0x1B1B2D36UL, 0x6E6EB2DCUL, 0x5A5AEEB4UL, 0xA0A0FB5BUL,
	0x5252F6A4UL, 0x3B3B4D76UL, 0xD6D661B7UL, 0xB3B3CE7DUL, 0x29297B52UL, 0xE3E33EDDUL, 0x2F2F715EUL, 0x84849713UL,
	0x5353F5A6UL, 0xD1D168B9UL, 0x00000000UL, 0xEDED2CC1UL, 0x20206040UL, 0xFCFC1FE3UL, 0xB1B1C879UL, 0x5B5BEDB6UL,
	0x6A6ABED4UL, 0xCBCB468DUL, 0xBEBED967UL, 0x39394B72UL, 0x4A4ADE94UL, 0x4C4CD498UL, 0x5858E8B0UL, 0xCFCF4A85UL,
	0xD0D06BBBUL, 0xEFEF2AC5UL, 0xAAAAE54FUL, 0xFBFB16EDUL, 0x4343C586UL, 0x4D4DD79AUL, 0x33335566UL, 0x85859411UL,
	0x4545CF8AUL, 0xF9F910E9UL, 0x02020604UL, 0x7F7F81FEUL, 0x5050F0A0UL, 0x3C3C4478UL, 0x9F9FBA25UL, 0xA8A8E34BUL,
	0x5151F3A2UL, 0xA3A3FE5DUL, 0x4040C080UL, 0x8F8F8A05UL, 0x9292AD3FUL, 0x9D9DBC21UL, 0x38384870UL, 0xF5F504F1UL,
	0xBCBCDF63UL, 0xB6B6C177UL, 0xDADA75AFUL, 0x21216342UL, 0x10103020UL, 0xFFFF1AE5UL, 0xF3F30EFDUL, 0xD2D26DBFUL,
	0xCDCD4C81UL, 0x0C0C1418UL, 0x13133526UL, 0xECEC2FC3UL, 0x5F5FE1BEUL, 0x9797A235UL, 0x4444CC88UL, 0x1717392EUL,
	0xC4C45793UL, 0xA7A7F255UL, 0x7E7E82FCUL, 0x3D3D477AUL, 0x6464ACC8UL, 0x5D5DE7BAUL, 0x19192B32UL, 0x737395E6UL,
	0x6060A0C0UL, 0x81819819UL, 0x4F4FD19EUL, 0xDCDC7FA3UL, 0x22226644UL, 0x2A2A7E54UL, 0x9090AB3BUL, 0x8888830BUL,
	0x4646CA8CUL, 0xEEEE29C7UL, 0xB8B8D36BUL, 0x14143C28UL, 0xDEDE79A7UL, 0x5E5EE2BCUL, 0x0B0B1D16UL, 0xDBDB76ADUL,
	0xE0E03BDBUL, 0x32325664UL, 0x3A3A4E74UL, 0x0A0A1E14UL, 0x4949DB92UL, 0x06060A0CUL, 0x24246C48UL, 0x5C5CE4B8UL,
	0xC2C25D9FUL, 0xD3D36EBDUL, 0xACACEF43UL, 0x6262A6C4UL, 0x9191A839UL, 0x9595A431UL, 0xE4E437D3UL, 0x79798BF2UL,
	0xE7E732D5UL, 0xC8C8438BUL, 0x3737596EUL, 0x6D6DB7DAUL, 0x8D8D8C01UL, 0xD5D564B1UL, 0x4E4ED29CUL, 0xA9A9E049UL,
	0x6C6CB4D8UL, 0x5656FAACUL, 0xF4F407F3UL, 0xEAEA25CFUL, 0x6565AFCAUL, 0x7A7A8EF4UL, 0xAEAEE947UL, 0x08081810UL,
	0xBABAD56FUL, 0x787888F0UL, 0x25256F4AUL, 0x2E2E725CUL, 0x1C1C2438UL, 0xA6A6F157UL, 0xB4B4C773UL, 0xC6C65197UL,
	0xE8E823CBUL, 0xDDDD7CA1UL, 0x74749CE8UL, 0x1F1F213EUL, 0x4B4BDD96UL, 0xBDBDDC61UL, 0x8B8B860DUL, 0x8A8A850FUL,
	0x707090E0UL, 0x3E3E427CUL, 0xB5B5C471UL, 0x6666AACCUL, 0x4848D890UL, 0x03030506UL, 0xF6F601F7UL, 0x0E0E121CUL,
	0x6161A3C2UL, 0x35355F6AUL, 0x5757F9AEUL, 0xB9B9D069UL, 0x86869117UL, 0xC1C15899UL, 0x1D1D273AUL, 0x9E9EB927UL,
	0xE1E138D9UL, 0xF8F813EBUL, 0x9898B32BUL, 0x11113322UL, 0x6969BBD2UL, 0xD9D970A9UL, 0x8E8E8907UL, 0x9494A733UL,
	0x9B9BB62DUL, 0x1E1E223CUL, 0x87879215UL, 0xE9E920C9UL, 0xCECE4987UL, 0x5555FFAAUL, 0x28287850UL, 0xDFDF7AA5UL,
	0x8C8C8F03UL, 0xA1A1F859UL, 0x89898009UL, 0x0D0D171AUL, 0xBFBFDA65UL, 0xE6E631D7UL, 0x4242C684UL, 0x6868B8D0UL,
	0x4141C382UL, 0x9999B029UL, 0x2D2D775AUL, 0x0F0F111EUL, 0xB0B0CB7BUL, 0x5454FCA8UL, 0xBBBBD66DUL, 0x16163A2CUL
};

class RCS::RcsState
{
public:

	SecureVector<uint> RoundKeys;
	SecureVector<byte> Associated;
	SecureVector<byte> Custom;
	SecureVector<byte> MacKey;
	SecureVector<byte> MacTag;
	SecureVector<byte> Name;
	std::vector<byte> Nonce;
	ulong Counter;
	ushort Rounds;
	StreamAuthenticators Authenticator;
	ShakeModes Mode;
	bool Encryption;
	bool Initialized;

	RcsState()
		:
		RoundKeys(0),
		Associated(0),
		Custom(0),
		MacKey(0),
		MacTag(0),
		Name(0),
		Nonce(BLOCK_SIZE, 0x00),
		Counter(0),
		Rounds(0),
		Authenticator(StreamAuthenticators::None),
		Mode(ShakeModes::None),
		Encryption(false),
		Initialized(false)
	{
	}

	RcsState(SecureVector<byte> &State)
		:
		RoundKeys(0),
		Associated(0),
		Custom(0),
		MacKey(0),
		MacTag(0),
		Name(0),
		Nonce(BLOCK_SIZE, 0x00),
		Counter(0),
		Rounds(0),
		Authenticator(StreamAuthenticators::None),
		Mode(ShakeModes::None),
		Encryption(false),
		Initialized(false)
	{
		DeSerialize(State);
	}

	~RcsState()
	{
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(uint));
		MemoryTools::Clear(Associated, 0, Associated.size());
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Name, 0, Name.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());

		Counter = 0;
		Rounds = 0;
		Authenticator = StreamAuthenticators::None;
		Mode = ShakeModes::None;
		Encryption = false;
		Initialized = false;
	}

	void DeSerialize(SecureVector<byte> &SecureState)
	{
		size_t soff;
		ushort vlen; 

		soff = 0;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		RoundKeys.resize(vlen / sizeof(uint));
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, RoundKeys, 0, vlen);
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		Associated.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, Associated, 0, Associated.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		Custom.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, Custom, 0, Custom.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		MacKey.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, MacKey, 0, MacKey.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		MacTag.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, MacTag, 0, MacTag.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		Name.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, Name, 0, Name.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &vlen, sizeof(ushort));
		Nonce.resize(vlen);
		soff += sizeof(ushort);
		MemoryTools::Copy(SecureState, soff, Nonce, 0, Nonce.size());
		soff += vlen;

		MemoryTools::CopyToObject(SecureState, soff, &Counter, sizeof(ulong));
		soff += sizeof(ulong);
		MemoryTools::CopyToObject(SecureState, soff, &Rounds, sizeof(ushort));
		soff += sizeof(ushort);

		MemoryTools::CopyToObject(SecureState, soff, &Authenticator, sizeof(StreamAuthenticators));
		soff += sizeof(StreamAuthenticators);
		MemoryTools::CopyToObject(SecureState, soff, &Mode, sizeof(ShakeModes));
		soff += sizeof(ShakeModes);

		MemoryTools::CopyToObject(SecureState, soff, &Encryption, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyToObject(SecureState, soff, &Initialized, sizeof(bool));
	}

	void Reset()
	{
		MemoryTools::Clear(RoundKeys, 0, RoundKeys.size() * sizeof(uint));
		MemoryTools::Clear(Associated, 0, Associated.size());
		MemoryTools::Clear(Custom, 0, Custom.size());
		MemoryTools::Clear(MacKey, 0, MacKey.size());
		MemoryTools::Clear(MacTag, 0, MacTag.size());
		MemoryTools::Clear(Name, 0, Name.size());
		MemoryTools::Clear(Nonce, 0, Nonce.size());

		Counter = 0;
		Rounds = 0;
		Encryption = false;
		Initialized = false;
	}

	SecureVector<byte> Serialize()
	{
		const size_t STASZE = (RoundKeys.size() * sizeof(uint)) + Associated.size() + Custom.size() + MacKey.size() + MacTag.size() +
			Name.size() + Nonce.size() + sizeof(ulong) + sizeof(ushort) + sizeof(StreamAuthenticators) + sizeof(ShakeModes) + (2 * sizeof(bool)) + (7 * sizeof(ushort));

		size_t soff;
		ushort vlen;
		SecureVector<byte> state(STASZE);

		soff = 0;
		vlen = static_cast<ushort>(RoundKeys.size() * sizeof(uint));
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(RoundKeys, 0, state, soff, static_cast<size_t>(vlen));
		soff += vlen;

		vlen = static_cast<ushort>(Associated.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(Associated, 0, state, soff, Associated.size());
		soff += Associated.size();

		vlen = static_cast<ushort>(Custom.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(Custom, 0, state, soff, Custom.size());
		soff += Custom.size();

		vlen = static_cast<ushort>(MacKey.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(MacKey, 0, state, soff, MacKey.size());
		soff += MacKey.size();

		vlen = static_cast<ushort>(MacTag.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(MacTag, 0, state, soff, MacTag.size());
		soff += MacTag.size();

		vlen = static_cast<ushort>(Name.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(Name, 0, state, soff, Name.size());
		soff += Name.size();

		vlen = static_cast<ushort>(Nonce.size());
		MemoryTools::CopyFromObject(&vlen, state, soff, sizeof(ushort));
		soff += sizeof(ushort);
		MemoryTools::Copy(Nonce, 0, state, soff, Nonce.size());
		soff += Nonce.size();

		MemoryTools::CopyFromObject(&Counter, state, soff, sizeof(ulong));
		soff += sizeof(ulong);
		MemoryTools::CopyFromObject(&Rounds, state, soff, sizeof(ushort));
		soff += sizeof(ushort);

		MemoryTools::CopyFromObject(&Authenticator, state, soff, sizeof(StreamAuthenticators));
		soff += sizeof(StreamAuthenticators);
		MemoryTools::CopyFromObject(&Mode, state, soff, sizeof(ShakeModes));
		soff += sizeof(ShakeModes);

		MemoryTools::CopyFromObject(&Encryption, state, soff, sizeof(bool));
		soff += sizeof(bool);
		MemoryTools::CopyFromObject(&Initialized, state, soff, sizeof(bool));

		return state;
	}
};

//~~~Constructor~~~//

RCS::RCS(StreamAuthenticators AuthenticatorType)
	:
	m_rcsState(new RcsState()),
	m_legalKeySizes { 
		SymmetricKeySize(32, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(64, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(128, BLOCK_SIZE, INFO_SIZE)},
	m_macAuthenticator(AuthenticatorType == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(AuthenticatorType)),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
}

RCS::RCS(SecureVector<byte> &State)
	:
	m_rcsState(State.size() > STATE_THRESHOLD ? new RcsState(State) :
		throw CryptoSymmetricException(std::string("RCS"), std::string("Constructor"), std::string("The State array is invalid!"), ErrorCodes::InvalidKey)),
	m_legalKeySizes{
		SymmetricKeySize(32, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(64, BLOCK_SIZE, INFO_SIZE),
		SymmetricKeySize(128, BLOCK_SIZE, INFO_SIZE)},
		m_macAuthenticator(m_rcsState->Authenticator == StreamAuthenticators::None ? nullptr :
		Helper::MacFromName::GetInstance(m_rcsState->Authenticator)),
	m_parallelProfile(BLOCK_SIZE, true, STATE_PRECACHED, true)
{
	if (m_rcsState->Authenticator != StreamAuthenticators::None)
	{
		// initialize the mac
		SymmetricKey kpm(m_rcsState->MacKey);
		m_macAuthenticator->Initialize(kpm);
	}
}

RCS::~RCS()
{
	if (m_macAuthenticator != nullptr)
	{
		m_macAuthenticator.reset(nullptr);
	}
}

//~~~Accessors~~~//

const StreamCiphers RCS::Enumeral()
{
	StreamAuthenticators auth;
	StreamCiphers tmpn;

	auth = IsAuthenticator() ? static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral()) : StreamAuthenticators::None;
	tmpn = StreamCipherConvert::FromDescription(StreamCiphers::RCS, auth);

	return tmpn;
}

const bool RCS::IsAuthenticator()
{
	return (m_macAuthenticator != nullptr);
}

const bool RCS::IsEncryption()
{
	return m_rcsState->Encryption;
}

const bool RCS::IsInitialized()
{
	return m_rcsState->Initialized;
}

const bool RCS::IsParallel()
{
	return m_parallelProfile.IsParallel();
}

const std::vector<SymmetricKeySize> &RCS::LegalKeySizes()
{
	return m_legalKeySizes;
}

const std::string RCS::Name()
{
	std::string name;

	name = StreamCipherConvert::ToName(Enumeral());

	return name;
}

const std::vector<byte> RCS::Nonce()
{
	return m_rcsState->Nonce;
}

const size_t RCS::ParallelBlockSize()
{
	return m_parallelProfile.ParallelBlockSize();
}

ParallelOptions &RCS::ParallelProfile()
{
	return m_parallelProfile;
}

const std::vector<byte> RCS::Tag()
{
	return SecureUnlock(m_rcsState->MacTag);
}

const void RCS::Tag(SecureVector<byte> &Output)
{
	SecureCopy(m_rcsState->MacTag, 0, Output, 0, m_rcsState->MacTag.size());
}

const size_t RCS::TagSize()
{
	return IsAuthenticator() ? m_macAuthenticator->TagSize() : 0;
}

//~~~Public Functions~~~//

void RCS::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	size_t i;
	uint tmpbk;

	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Invalid key size; key must be one of the LegalKeySizes in length."), ErrorCodes::InvalidKey);
	}
	if (Parameters.KeySizes().NonceSize() != BLOCK_SIZE)
	{
		throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("Requires a nonce equal in size to the ciphers block size!"), ErrorCodes::InvalidNonce);
	}

	if (m_parallelProfile.IsParallel())
	{
		if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() < m_parallelProfile.ParallelMinimumSize() || m_parallelProfile.ParallelBlockSize() > m_parallelProfile.ParallelMaximumSize())
		{
			throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The parallel block size is out of bounds!"), ErrorCodes::InvalidSize);
		}
		if (m_parallelProfile.IsParallel() && m_parallelProfile.ParallelBlockSize() % m_parallelProfile.ParallelMinimumSize() != 0)
		{
			throw CryptoSymmetricException(Name(), std::string("Initialize"), std::string("The parallel block size must be evenly aligned to the ParallelMinimumSize!"), ErrorCodes::InvalidParam);
		}
	}

	// reset for a new key
	if (IsInitialized())
	{
		Reset();
	}

	// set up the state members
	m_rcsState->Authenticator = m_macAuthenticator != nullptr ? static_cast<StreamAuthenticators>(m_macAuthenticator->Enumeral()) : StreamAuthenticators::None;
	// set the initial processed-bytes count to one
	m_rcsState->Counter = 1;
	// set the number of rounds
	m_rcsState->Rounds = Parameters.KeySizes().KeySize() != 128 ? static_cast<ushort>((Parameters.KeySizes().KeySize() / 4)) + 14 : 38;

	// create the cSHAKE customization string
	m_rcsState->Custom.resize(Parameters.KeySizes().InfoSize() + OMEGA_INFO.size());
	// copy the version string to the customization parameter
	MemoryTools::Copy(OMEGA_INFO, 0, m_rcsState->Custom, 0, OMEGA_INFO.size());
	// copy the user defined string to the customization parameter
	MemoryTools::Copy(Parameters.Info(), 0, m_rcsState->Custom, OMEGA_INFO.size(), Parameters.KeySizes().InfoSize());

	// create the cSHAKE name string
	std::string tmpn = Name();
	// add mac counter, key-size bits, and algorithm name to name string
	m_rcsState->Name.resize(sizeof(ulong) + sizeof(ushort) + tmpn.size());
	// mac counter is always first 8 bytes
	IntegerTools::Le64ToBytes(m_rcsState->Counter, m_rcsState->Name, 0);
	// add the cipher key size in bits as an unsigned short integer
	ushort kbits = static_cast<ushort>(Parameters.KeySizes().KeySize() * 8);
	IntegerTools::Le16ToBytes(kbits, m_rcsState->Name, sizeof(ulong));
	// copy the name string to state
	MemoryTools::CopyFromObject(tmpn.data(), m_rcsState->Name, sizeof(ulong) + sizeof(ushort), tmpn.size());

	// copy the nonce to state
	MemoryTools::Copy(Parameters.Nonce(), 0, m_rcsState->Nonce, 0, BLOCK_SIZE);

	// cipher key size determines key expansion function and Mac generator type; 256 or 512-bit
	m_rcsState->Mode = (Parameters.KeySizes().KeySize() == 64) ? ShakeModes::SHAKE512 : (Parameters.KeySizes().KeySize() == 32) ? ShakeModes::SHAKE256 : ShakeModes::SHAKE1024;
	Kdf::SHAKE gen(m_rcsState->Mode);
	// initialize cSHAKE with k,c,n
	gen.Initialize(Parameters.SecureKey(), m_rcsState->Custom, m_rcsState->Name);

	// size the round key array
	const size_t RNKLEN = (BLOCK_SIZE / sizeof(uint)) * (m_rcsState->Rounds + 1);
	m_rcsState->RoundKeys.resize(RNKLEN);
	// generate the round keys to a temporary byte array
	SecureVector<byte> tmpr(RNKLEN * sizeof(uint));
	// generate the ciphers round-keys
	gen.Generate(tmpr);

	// realign in big endian format for ACS test vectors; RCS is the fallback to the AES-NI implementation
	for (i = 0; i < tmpr.size(); i += sizeof(uint))
	{
		tmpbk = IntegerTools::BeBytesTo32(tmpr, i);
		IntegerTools::Le32ToBytes(tmpbk, tmpr, i);
	}

	// copy bytes to round-key array
#if defined(CEX_IS_LITTLE_ENDIAN)
	MemoryTools::Copy(tmpr, 0, m_rcsState->RoundKeys, 0, tmpr.size());
#else
	for (size_t i = 0; i < RNKLEN; ++i)
	{
		m_rcsState->RoundKeys[i] = IntegerTools::LeBytesTo32(tmpr, i * sizeof(uint));
	}
#endif

	MemoryTools::Clear(tmpr, 0, tmpr.size());

	if (IsAuthenticator())
	{
		// generate the mac key
		SymmetricKeySize ks = m_macAuthenticator->LegalKeySizes()[1];
		SecureVector<byte> mack(ks.KeySize());
		gen.Generate(mack);
		// initialize the mac
		SymmetricKey kpm(mack);
		m_macAuthenticator->Initialize(kpm);
		// store the key
		m_rcsState->MacKey.resize(mack.size());
		SecureMove(mack, m_rcsState->MacKey, 0);
		m_rcsState->MacTag.resize(TagSize());
	}

	m_rcsState->Encryption = Encryption;
	m_rcsState->Initialized = true;
}

void RCS::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_parallelProfile.ProcessorCount())
	{
		throw CryptoSymmetricException(Name(), std::string("ParallelMaxDegree"), std::string("Degree setting is invalid!"), ErrorCodes::NotSupported);
	}

	m_parallelProfile.SetMaxDegree(Degree);
}

void RCS::SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (!IsInitialized())
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_macAuthenticator == nullptr)
	{
		throw CryptoSymmetricException(Name(), std::string("SetAssociatedData"), std::string("The cipher has not been configured for authentication!"), ErrorCodes::IllegalOperation);
	}

	// store the associated data
	m_rcsState->Associated.resize(Length);
	MemoryTools::Copy(Input, Offset, m_rcsState->Associated, 0, Length);
}

void RCS::Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CEXASSERT(IsInitialized(), "The cipher mode has not been initialized!");
	CEXASSERT(IntegerTools::Min(Input.size() - InOffset, Output.size() - OutOffset) >= Length, "The data arrays are smaller than the block-size!");

	if (IsEncryption())
	{
		if (IsAuthenticator())
		{
			if (Output.size() < Length + OutOffset + m_macAuthenticator->TagSize())
			{
				throw CryptoSymmetricException(Name(), std::string("Transform"), std::string("The vector is not long enough to add the MAC code!"), ErrorCodes::InvalidSize);
			}

			// add the starting position of the nonce
			m_macAuthenticator->Update(m_rcsState->Nonce, 0, BLOCK_SIZE);
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Output, OutOffset, Length);
			// update the processed bytes counter
			m_rcsState->Counter += Length;
			// finalize the mac and copy the tag to the end of the output stream
			Finalize(m_rcsState, m_macAuthenticator);
			MemoryTools::Copy(m_rcsState->MacTag, 0, Output, OutOffset + Length, m_rcsState->MacTag.size());
		}
		else
		{
			// encrypt the stream
			Process(Input, InOffset, Output, OutOffset, Length);
		}
	}
	else
	{
		if (IsAuthenticator())
		{
			// add the starting position of the nonce
			m_macAuthenticator->Update(m_rcsState->Nonce, 0, BLOCK_SIZE);
			// update the mac with the ciphertext
			m_macAuthenticator->Update(Input, InOffset, Length);
			// update the processed bytes counter
			m_rcsState->Counter += Length;
			// finalize the mac and verify
			Finalize(m_rcsState, m_macAuthenticator);

			if (!IntegerTools::Compare(Input, InOffset + Length, m_rcsState->MacTag, 0, m_rcsState->MacTag.size()))
			{
				throw CryptoAuthenticationFailure(Name(), std::string("Transform"), std::string("The authentication tag does not match!"), ErrorCodes::AuthenticationFailure);
			}
		}

		// decrypt the stream
		Process(Input, InOffset, Output, OutOffset, Length);
	}
}

//~~~Private Functions~~~//

void RCS::Finalize(std::unique_ptr<RcsState> &State, std::unique_ptr<IMac> &Authenticator)
{
	std::vector<byte> mctr(sizeof(ulong));
	ulong mlen;

	// 1.0c: add the total number of bytes processed by the mac, including this terminating string
	mlen = State->Counter + State->Nonce.size() + State->Associated.size() + mctr.size();
	IntegerTools::LeIncrease8(mctr, mlen);

	// 1.0c: add the associated data to the mac
	if (State->Associated.size() != 0)
	{
		Authenticator->Update(SecureUnlock(State->Associated), 0, State->Associated.size());
		// clear the associated data, reset for each transformation, 
		// assignable with a call to SetAssociatedData before each transform call
		SecureClear(State->Associated);
	}

	// add the termination string to the mac
	Authenticator->Update(mctr, 0, mctr.size());

	// finalize the mac code to state
	Authenticator->Finalize(State->MacTag, 0);

	// name string is an unsigned 64-bit bytes counter + key-size + cipher-name
	// the state counter is the number of bytes processed by the cipher
	IntegerTools::Le64ToBytes(State->Counter, State->Name, 0);

	// extract the new mac key: cSHAKE(k,c,n)
	Kdf::SHAKE gen(State->Mode);
	gen.Initialize(State->MacKey, State->Custom, State->Name);
	SymmetricKeySize ks = Authenticator->LegalKeySizes()[1];
	SecureVector<byte> mack(ks.KeySize());
	gen.Generate(mack);

	// re-initialize the generator with the new key
	SymmetricKey kpm(mack);
	Authenticator->Initialize(kpm);
	// store the new key and erase the temporary key
	SecureMove(mack, State->MacKey, 0);
}

void RCS::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::vector<byte> &Counter)
{
	size_t bctr;

	bctr = 0;

#if defined(__AVX512__)
	const size_t AVX512BLK = 16 * BLOCK_SIZE;
	if (Length >= AVX512BLK)
	{
		const size_t PBKALN = Length - (Length % AVX512BLK);
		std::vector<byte> tmpc(AVX512BLK);

		// stagger counters and process 8 blocks with avx512
		while (bctr != PBKALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 32, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 64, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 96, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 128, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 160, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 192, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 224, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 256, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 288, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 320, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 352, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 384, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 416, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 448, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 480, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			Transform4096(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVX512BLK;
		}
	}
#elif defined(__AVX2__)
	const size_t AVX2BLK = 8 * BLOCK_SIZE;
	if (Length >= AVX2BLK)
	{
		const size_t PBKALN = Length - (Length % AVX2BLK);
		std::vector<byte> tmpc(AVX2BLK);

		// stagger counters and process 8 blocks with avx2
		while (bctr != PBKALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 32, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 64, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 96, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 128, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 160, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 192, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 224, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			Transform2048(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVX2BLK;
}
	}
#elif defined(__AVX__)
	const size_t AVXBLK = 4 * BLOCK_SIZE;
	if (Length >= AVXBLK)
	{
		const size_t PBKALN = Length - (Length % AVXBLK);
		std::vector<byte> tmpc(AVXBLK);

		// 4 blocks with avx
		while (bctr != PBKALN)
		{
			MemoryTools::Copy(Counter, 0, tmpc, 0, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 32, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 64, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			MemoryTools::Copy(Counter, 0, tmpc, 96, BLOCK_SIZE);
			IntegerTools::LeIncrement(Counter, 16);
			Transform1024(tmpc, 0, Output, OutOffset + bctr);
			bctr += AVXBLK;
		}
	}
#endif

	const size_t BLKALN = Length - (Length % BLOCK_SIZE);
	while (bctr != BLKALN)
	{
		Transform256(Counter, 0, Output, OutOffset + bctr);
		IntegerTools::LeIncrement(Counter, 16);
		bctr += BLOCK_SIZE;
	}

	if (bctr != Length)
	{
		std::vector<byte> otp(BLOCK_SIZE);
		Transform256(Counter, 0, otp, 0);
		IntegerTools::LeIncrement(Counter, 16);
		const size_t RMDLEN = Length % BLOCK_SIZE;
		MemoryTools::Copy(otp, 0, Output, OutOffset + (Length - RMDLEN), RMDLEN);
	}
}

CEX_OPTIMIZE_IGNORE
void RCS::PrefetchRoundKey(const SecureVector<uint> &Rkey)
{
	// timing defence: pre-load the round-key array into l1 cache
	MemoryTools::PrefetchL1(Rkey, 0, Rkey.size() * sizeof(uint));
}
CEX_OPTIMIZE_RESUME

CEX_OPTIMIZE_IGNORE
void RCS::PrefetchSbox()
{
	// timing defence: pre-load sbox into l1 cache
	MemoryTools::PrefetchL1(SBox, 0, SBox.size());
}
CEX_OPTIMIZE_RESUME

CEX_OPTIMIZE_IGNORE
void RCS::PrefetchTables()
{
	// timing defence: pre-load multiplication tables into l1 cache
	MemoryTools::PrefetchL1(MT0, 0, MT0.size() * sizeof(uint));
	MemoryTools::PrefetchL1(MT1, 0, MT1.size() * sizeof(uint));
	MemoryTools::PrefetchL1(MT2, 0, MT2.size() * sizeof(uint));
	MemoryTools::PrefetchL1(MT3, 0, MT3.size() * sizeof(uint));

}
CEX_OPTIMIZE_RESUME

void RCS::Process(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	size_t i;

	const size_t PRLBLK = m_parallelProfile.ParallelBlockSize();

	if (m_parallelProfile.IsParallel() && Length >= PRLBLK)
	{
		const size_t BLKCNT = Length / PRLBLK;

		for (i = 0; i < BLKCNT; ++i)
		{
			ProcessParallel(Input, InOffset + (i * PRLBLK), Output, OutOffset + (i * PRLBLK), PRLBLK);
		}

		const size_t RMDLEN = Length - (PRLBLK * BLKCNT);

		if (RMDLEN != 0)
		{
			const size_t BLKOFT = (PRLBLK * BLKCNT);
			ProcessSequential(Input, InOffset + BLKOFT, Output, OutOffset + BLKOFT, RMDLEN);
		}
	}
	else
	{
		ProcessSequential(Input, InOffset, Output, OutOffset, Length);
	}
}

void RCS::ProcessParallel(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	const size_t OUTLEN = Output.size() - OutOffset < Length ? Output.size() - OutOffset : Length;
	const size_t CNKLEN = m_parallelProfile.ParallelBlockSize() / m_parallelProfile.ParallelMaxDegree();
	const size_t CTRLEN = (CNKLEN / BLOCK_SIZE);
	std::vector<byte> tmpc(BLOCK_SIZE);

	Utility::ParallelTools::ParallelFor(0, m_parallelProfile.ParallelMaxDegree(), [this, &Input, InOffset, &Output, OutOffset, &tmpc, CNKLEN, CTRLEN](size_t i)
	{
		// thread level counter
		std::vector<byte> thdc(BLOCK_SIZE);
		// offset counter by chunk size / block size  
		IntegerTools::LeIncrease8(m_rcsState->Nonce, thdc, static_cast<uint>(CTRLEN * i));
		const size_t STMPOS = i * CNKLEN;
		// generate random at output offset
		this->Generate(Output, OutOffset + STMPOS, CNKLEN, thdc);
		// xor with input at offsets
		MemoryTools::XOR(Input, InOffset + STMPOS, Output, OutOffset + STMPOS, CNKLEN);

		// store last counter
		if (i == m_parallelProfile.ParallelMaxDegree() - 1)
		{
			MemoryTools::Copy(thdc, 0, tmpc, 0, BLOCK_SIZE);
		}
	});

	// copy last counter to class variable
	MemoryTools::Copy(tmpc, 0, m_rcsState->Nonce, 0, BLOCK_SIZE);

	// last block processing
	const size_t ALNLEN = CNKLEN * m_parallelProfile.ParallelMaxDegree();
	if (ALNLEN < OUTLEN)
	{
		const size_t FNLLEN = (Output.size() - OutOffset) % ALNLEN;
		Generate(Output, ALNLEN, FNLLEN, m_rcsState->Nonce);

		for (size_t i = ALNLEN; i < OUTLEN; i++)
		{
			Output[i] ^= Input[i];
		}
	}
}

void RCS::ProcessSequential(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	// get block aligned
	const size_t ALNLEN = Length - (Length % BLOCK_SIZE);
	size_t i;

	// generate random
	Generate(Output, OutOffset, Length, m_rcsState->Nonce);

	if (ALNLEN != 0)
	{
		MemoryTools::XOR(Input, InOffset, Output, OutOffset, ALNLEN);
	}

	// get the remaining bytes
	if (ALNLEN != Length)
	{
		for (i = ALNLEN; i < Length; ++i)
		{
			Output[i + OutOffset] ^= Input[i + InOffset];
		}
	}
}

void RCS::Reset()
{
	m_rcsState->Reset();

	if (IsAuthenticator())
	{
		m_macAuthenticator->Reset();
	}

	m_parallelProfile.Calculate(m_parallelProfile.IsParallel(), m_parallelProfile.ParallelBlockSize(), m_parallelProfile.ParallelMaxDegree());
}

SecureVector<byte> RCS::Serialize()
{
	SecureVector<byte> tmps = m_rcsState->Serialize();

	return tmps;
}

void RCS::Transform256(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	const size_t RNDCNT = m_rcsState->RoundKeys.size() - 8;
	size_t kctr;
	uint X0;
	uint X1;
	uint X2;
	uint X3;
	uint X4;
	uint X5;
	uint X6;
	uint X7;
	uint Y0;
	uint Y1;
	uint Y2;
	uint Y3;
	uint Y4;
	uint Y5;
	uint Y6;
	uint Y7;

	// pre-load the round key array into l1 as a timing defence
#if defined(CEX_PREFETCH_RHX_TABLES)
	PrefetchRoundKey(m_rcsState->RoundKeys);
#endif

	// round 0
	X0 = IntegerTools::BeBytesTo32(Input, InOffset) ^ m_rcsState->RoundKeys[0];
	X1 = IntegerTools::BeBytesTo32(Input, InOffset + 4) ^ m_rcsState->RoundKeys[1];
	X2 = IntegerTools::BeBytesTo32(Input, InOffset + 8) ^ m_rcsState->RoundKeys[2];
	X3 = IntegerTools::BeBytesTo32(Input, InOffset + 12) ^ m_rcsState->RoundKeys[3];
	X4 = IntegerTools::BeBytesTo32(Input, InOffset + 16) ^ m_rcsState->RoundKeys[4];
	X5 = IntegerTools::BeBytesTo32(Input, InOffset + 20) ^ m_rcsState->RoundKeys[5];
	X6 = IntegerTools::BeBytesTo32(Input, InOffset + 24) ^ m_rcsState->RoundKeys[6];
	X7 = IntegerTools::BeBytesTo32(Input, InOffset + 28) ^ m_rcsState->RoundKeys[7];

	// pre-load the multiplication tables
#if defined(CEX_PREFETCH_RHX_TABLES)
	PrefetchTables();
#endif

	// round 1
	Y0 = MT0[static_cast<byte>(X0 >> 24)] ^ MT1[static_cast<byte>(X1 >> 16)] ^ MT2[static_cast<byte>(X3 >> 8)] ^ MT3[static_cast<byte>(X4)] ^ m_rcsState->RoundKeys[8];
	Y1 = MT0[static_cast<byte>(X1 >> 24)] ^ MT1[static_cast<byte>(X2 >> 16)] ^ MT2[static_cast<byte>(X4 >> 8)] ^ MT3[static_cast<byte>(X5)] ^ m_rcsState->RoundKeys[9];
	Y2 = MT0[static_cast<byte>(X2 >> 24)] ^ MT1[static_cast<byte>(X3 >> 16)] ^ MT2[static_cast<byte>(X5 >> 8)] ^ MT3[static_cast<byte>(X6)] ^ m_rcsState->RoundKeys[10];
	Y3 = MT0[static_cast<byte>(X3 >> 24)] ^ MT1[static_cast<byte>(X4 >> 16)] ^ MT2[static_cast<byte>(X6 >> 8)] ^ MT3[static_cast<byte>(X7)] ^ m_rcsState->RoundKeys[11];
	Y4 = MT0[static_cast<byte>(X4 >> 24)] ^ MT1[static_cast<byte>(X5 >> 16)] ^ MT2[static_cast<byte>(X7 >> 8)] ^ MT3[static_cast<byte>(X0)] ^ m_rcsState->RoundKeys[12];
	Y5 = MT0[static_cast<byte>(X5 >> 24)] ^ MT1[static_cast<byte>(X6 >> 16)] ^ MT2[static_cast<byte>(X0 >> 8)] ^ MT3[static_cast<byte>(X1)] ^ m_rcsState->RoundKeys[13];
	Y6 = MT0[static_cast<byte>(X6 >> 24)] ^ MT1[static_cast<byte>(X7 >> 16)] ^ MT2[static_cast<byte>(X1 >> 8)] ^ MT3[static_cast<byte>(X2)] ^ m_rcsState->RoundKeys[14];
	Y7 = MT0[static_cast<byte>(X7 >> 24)] ^ MT1[static_cast<byte>(X0 >> 16)] ^ MT2[static_cast<byte>(X2 >> 8)] ^ MT3[static_cast<byte>(X3)] ^ m_rcsState->RoundKeys[15];

	kctr = 16;
	while (kctr != RNDCNT)
	{
		X0 = MT0[static_cast<byte>(Y0 >> 24)] ^ MT1[static_cast<byte>(Y1 >> 16)] ^ MT2[static_cast<byte>(Y3 >> 8)] ^ MT3[static_cast<byte>(Y4)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X1 = MT0[static_cast<byte>(Y1 >> 24)] ^ MT1[static_cast<byte>(Y2 >> 16)] ^ MT2[static_cast<byte>(Y4 >> 8)] ^ MT3[static_cast<byte>(Y5)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X2 = MT0[static_cast<byte>(Y2 >> 24)] ^ MT1[static_cast<byte>(Y3 >> 16)] ^ MT2[static_cast<byte>(Y5 >> 8)] ^ MT3[static_cast<byte>(Y6)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X3 = MT0[static_cast<byte>(Y3 >> 24)] ^ MT1[static_cast<byte>(Y4 >> 16)] ^ MT2[static_cast<byte>(Y6 >> 8)] ^ MT3[static_cast<byte>(Y7)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X4 = MT0[static_cast<byte>(Y4 >> 24)] ^ MT1[static_cast<byte>(Y5 >> 16)] ^ MT2[static_cast<byte>(Y7 >> 8)] ^ MT3[static_cast<byte>(Y0)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X5 = MT0[static_cast<byte>(Y5 >> 24)] ^ MT1[static_cast<byte>(Y6 >> 16)] ^ MT2[static_cast<byte>(Y0 >> 8)] ^ MT3[static_cast<byte>(Y1)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X6 = MT0[static_cast<byte>(Y6 >> 24)] ^ MT1[static_cast<byte>(Y7 >> 16)] ^ MT2[static_cast<byte>(Y1 >> 8)] ^ MT3[static_cast<byte>(Y2)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		X7 = MT0[static_cast<byte>(Y7 >> 24)] ^ MT1[static_cast<byte>(Y0 >> 16)] ^ MT2[static_cast<byte>(Y2 >> 8)] ^ MT3[static_cast<byte>(Y3)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y0 = MT0[static_cast<byte>(X0 >> 24)] ^ MT1[static_cast<byte>(X1 >> 16)] ^ MT2[static_cast<byte>(X3 >> 8)] ^ MT3[static_cast<byte>(X4)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y1 = MT0[static_cast<byte>(X1 >> 24)] ^ MT1[static_cast<byte>(X2 >> 16)] ^ MT2[static_cast<byte>(X4 >> 8)] ^ MT3[static_cast<byte>(X5)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y2 = MT0[static_cast<byte>(X2 >> 24)] ^ MT1[static_cast<byte>(X3 >> 16)] ^ MT2[static_cast<byte>(X5 >> 8)] ^ MT3[static_cast<byte>(X6)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y3 = MT0[static_cast<byte>(X3 >> 24)] ^ MT1[static_cast<byte>(X4 >> 16)] ^ MT2[static_cast<byte>(X6 >> 8)] ^ MT3[static_cast<byte>(X7)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y4 = MT0[static_cast<byte>(X4 >> 24)] ^ MT1[static_cast<byte>(X5 >> 16)] ^ MT2[static_cast<byte>(X7 >> 8)] ^ MT3[static_cast<byte>(X0)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y5 = MT0[static_cast<byte>(X5 >> 24)] ^ MT1[static_cast<byte>(X6 >> 16)] ^ MT2[static_cast<byte>(X0 >> 8)] ^ MT3[static_cast<byte>(X1)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y6 = MT0[static_cast<byte>(X6 >> 24)] ^ MT1[static_cast<byte>(X7 >> 16)] ^ MT2[static_cast<byte>(X1 >> 8)] ^ MT3[static_cast<byte>(X2)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
		Y7 = MT0[static_cast<byte>(X7 >> 24)] ^ MT1[static_cast<byte>(X0 >> 16)] ^ MT2[static_cast<byte>(X2 >> 8)] ^ MT3[static_cast<byte>(X3)] ^ m_rcsState->RoundKeys[kctr];
		++kctr;
	}

	// pre-load the s-box
#if defined(CEX_PREFETCH_RHX_TABLES)
	PrefetchSbox();
#endif

	// final round
	Output[OutOffset] = static_cast<byte>(SBox[static_cast<byte>(Y0 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 1] = static_cast<byte>(SBox[static_cast<byte>(Y1 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 2] = static_cast<byte>(SBox[static_cast<byte>(Y3 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 3] = static_cast<byte>(SBox[static_cast<byte>(Y4)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 4] = static_cast<byte>(SBox[static_cast<byte>(Y1 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 5] = static_cast<byte>(SBox[static_cast<byte>(Y2 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 6] = static_cast<byte>(SBox[static_cast<byte>(Y4 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 7] = static_cast<byte>(SBox[static_cast<byte>(Y5)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 8] = static_cast<byte>(SBox[static_cast<byte>(Y2 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 9] = static_cast<byte>(SBox[static_cast<byte>(Y3 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 10] = static_cast<byte>(SBox[static_cast<byte>(Y5 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 11] = static_cast<byte>(SBox[static_cast<byte>(Y6)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 12] = static_cast<byte>(SBox[static_cast<byte>(Y3 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 13] = static_cast<byte>(SBox[static_cast<byte>(Y4 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 14] = static_cast<byte>(SBox[static_cast<byte>(Y6 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 15] = static_cast<byte>(SBox[static_cast<byte>(Y7)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 16] = static_cast<byte>(SBox[static_cast<byte>(Y4 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 17] = static_cast<byte>(SBox[static_cast<byte>(Y5 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 18] = static_cast<byte>(SBox[static_cast<byte>(Y7 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 19] = static_cast<byte>(SBox[static_cast<byte>(Y0)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 20] = static_cast<byte>(SBox[static_cast<byte>(Y5 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 21] = static_cast<byte>(SBox[static_cast<byte>(Y6 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 22] = static_cast<byte>(SBox[static_cast<byte>(Y0 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 23] = static_cast<byte>(SBox[static_cast<byte>(Y1)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 24] = static_cast<byte>(SBox[static_cast<byte>(Y6 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 25] = static_cast<byte>(SBox[static_cast<byte>(Y7 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 26] = static_cast<byte>(SBox[static_cast<byte>(Y1 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 27] = static_cast<byte>(SBox[static_cast<byte>(Y2)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
	++kctr;
	Output[OutOffset + 28] = static_cast<byte>(SBox[static_cast<byte>(Y7 >> 24)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 24));
	Output[OutOffset + 29] = static_cast<byte>(SBox[static_cast<byte>(Y0 >> 16)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 16));
	Output[OutOffset + 30] = static_cast<byte>(SBox[static_cast<byte>(Y2 >> 8)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr] >> 8));
	Output[OutOffset + 31] = static_cast<byte>(SBox[static_cast<byte>(Y3)] ^ static_cast<byte>(m_rcsState->RoundKeys[kctr]));
}

void RCS::Transform1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Transform256(Input, InOffset, Output, OutOffset);
	Transform256(Input, InOffset + 32, Output, OutOffset + 32);
	Transform256(Input, InOffset + 64, Output, OutOffset + 64);
	Transform256(Input, InOffset + 96, Output, OutOffset + 96);
}

void RCS::Transform2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Transform1024(Input, InOffset, Output, OutOffset);
	Transform1024(Input, InOffset + 128, Output, OutOffset + 128);
}

void RCS::Transform4096(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
{
	Transform2048(Input, InOffset, Output, OutOffset);
	Transform2048(Input, InOffset + 256, Output, OutOffset + 256);
}

NAMESPACE_STREAMEND
