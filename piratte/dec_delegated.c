#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"

char* usage =
		"Usage: easier-dec_delegated PUB_KEY_A PUB_KEY_B DEL_PRIV_KEY_ABC LK_B LK_C CT1.cpabe.proxy CT2.cpabe.proxy \n"
		"\n"
		"Decrypt CT1/CT2.cpabe.proxy using delegated private key DEL_PRIV_KEY_ABC, assuming public key\n"
		"PUB_KEY_A and PUB_KEY_B, and lambda files LK_B and LK_C. The decrypted file will be written as CT1.\n"
		"Use of the -o option overrides this behavior. \n"
		"CT1.cpabe.proxy is the converted file from PROXY of A\n"
		"CT2.cpabe.proxy is the converted file from PROXY of B\n"
		"\n"
		"Mandatory arguments to long options are mandatory for short options too.\n\n"
		" -h, --help               print this message\n\n"
		" -k, --keep-input-file    don't delete original file\n\n"
		" -v, --version            print version information\n\n"
		" -o, --output FILE        write output to FILE\n\n"
		" -d, --deterministic      use deterministic \"random\" numbers\n"
		"                          (only for debugging)\n\n"
		"";

char* pub_fileA = 0;
char* pub_fileB = 0;
char* del_prv_file = 0;
char* lambdaAB_file = 0;
char* lambdaBC_file = 0;
char* in_fileAB = 0;
char* in_fileBC = 0;
char* out_file = 0;
int keep = 0;

void
parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
		if( !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-k") || !strcmp(argv[i], "--keep-input-file") )
		{
			keep = 1;
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-dec_delegated");
			exit(0);
		}
		else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
		{
			if( ++i >= argc )
				die(usage);
			else
				out_file = argv[i];
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !pub_fileA )
		{
			pub_fileA = argv[i];
		}
		else if( !pub_fileB )
		{
			pub_fileB = argv[i];
		}
		else if( !del_prv_file )
		{
			del_prv_file = argv[i];
		}
		else if(!lambdaAB_file)
		{
			lambdaAB_file = argv[i];
		}
		else if(!lambdaBC_file)
		{
			lambdaBC_file = argv[i];
		}
		else if( !in_fileAB )
		{
			in_fileAB = argv[i];
		}
		else if( !in_fileBC )
		{
			in_fileBC = argv[i];
		}
		else
			die(usage);

	if( !pub_fileA || !pub_fileB || !del_prv_file || !lambdaAB_file || !lambdaBC_file || !in_fileAB || !in_fileBC )
		die(usage);

	if( !out_file )
	{
		if( strlen(in_fileAB) > 12 && !strcmp(in_fileAB + strlen(in_fileAB) - 12, ".cpabe.proxy") )
			out_file = g_strndup(in_fileAB, strlen(in_fileAB) - 12);
		else
			out_file = strdup(in_fileAB);
	}

	if( keep && !strcmp(in_fileAB, out_file) )
		die("cannot keep input file when decrypting file in place (try -o)\n");
}

int
main( int argc, char** argv )
{
	bswabe_pub_t* pubA;
	bswabe_pub_t* pubB;
	bswabe_del_prv_t* del_prv;
	element_t lambda_AB;
	element_t lambda_BC;
	element_t m;

	int file_lenAB = 0;
	int file_lenBC = 0;

	int offset1 = 0;
	int offset2 = 0;

	GByteArray* aes_bufAB;
	GByteArray* pltAB;
	GByteArray* cph_bufAB;

	GByteArray* aes_bufBC;
	GByteArray* pltBC;
	GByteArray* cph_bufBC;

	bswabe_cph_t* cphAB;
	bswabe_cph_t* cphBC;

	parse_args(argc, argv);

	pubA = bswabe_pub_unserialize(suck_file(pub_fileA), 1);
	pubB = bswabe_pub_unserialize(suck_file(pub_fileB), 1);
	del_prv = bswabe_del_prv_unserialize(pubB, suck_file(del_prv_file), 1);

	bswabe_element_init_Zr(lambda_AB, pubA); /*from proxy of A*/
	unserialize_element(suck_file(lambdaAB_file), &offset1, lambda_AB);

	bswabe_element_init_Zr(lambda_BC, pubB); /*from proxy of B*/
	unserialize_element(suck_file(lambdaBC_file), &offset2, lambda_BC);

	char* in_aes_file = g_strdup_printf("%s.cpaes", g_strndup(in_fileAB, strlen(in_fileAB) - 12));
	read_aes_file(in_aes_file, &file_lenAB, &aes_bufAB);

	read_cph_file(in_fileAB, &cph_bufAB);
	cphAB = bswabe_cph_unserialize(pubA, cph_bufAB, 1, 1);

	read_cph_file(in_fileBC, &cph_bufBC);
	cphBC = bswabe_cph_unserialize(pubB, cph_bufBC, 1, 1);

	if( !bswabe_dec_delegated( pubB, del_prv, cphAB, cphBC,  m,  lambda_AB,  lambda_BC) )
		die("%s", bswabe_error());

	bswabe_cph_free(cphAB, 1);
	bswabe_cph_free(cphBC, 1);

	pltAB = aes_128_cbc_decrypt(aes_bufAB, m);
	g_byte_array_set_size(pltAB, file_lenAB);
	g_byte_array_free(aes_bufAB, 1);

	spit_file(out_file, pltAB, 1);

	element_clear(m);
	element_clear(lambda_AB);
	element_clear(lambda_BC);

	if(!keep)
	{
		unlink(in_fileAB);
		unlink(in_fileBC);
	}

	return 0;
}