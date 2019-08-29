#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"

char* usage =
		"Usage: easier-convert [OPTION ...] PUB_KEY CIPHER_FILE PROXY_KEY USER_ID_FILE\n"
		"Take CIPHER_FILE (.cpabe format) and convert it to CIPHER_FILE.proxy \n"
		"using PUB_KEY, PROXY_KEY, and USER_ID_FILE,\" \n"
		"output lagrange coefficient to lambda_k unless -o or -l option is indicated \n"
		"Mandatory arguments to long options are mandatory for short options too.\n\n"
		" -h, --help					print this message\n\n"
		" -o, --output FILE				write converted ciphertext to FILE.cpabe.proxy"
		" -l, --out-lambda	LAMBDA_FILE	write lambda_k to LAMBDA_FILE\n\n"
		" -k, --keep					keep the cpabe file, required for delegated decryption"
		" -v, --version            		print version information\n\n"
		" -d, --deterministic      		use deterministic \"random\" numbers\n"
		"                          		(only for debugging)\n\n"
		"";

char* pub_file   = 0;
char* in_file    = 0;
char* rvk_file   = 0;
char* out_file   = 0;
char* u_k_file   = 0;
char u_k_str[100];
char* lambda_file= 0;
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
		else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
		{
			if( ++i >= argc )
				die(usage);
			else
				out_file = argv[i];
		}
		else if( !strcmp(argv[i], "-l") || !strcmp(argv[i], "--out-lambda") )
		{
			if( ++i >= argc )
				die(usage);
			else
				lambda_file = argv[i];
		}
		else if( !strcmp(argv[i], "-k") || !strcmp(argv[i], "--keep") )
		{
			keep = 1;
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-convert");
			exit(0);
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !in_file )
		{
			in_file = argv[i];
		}
		else if( !rvk_file )
		{
			rvk_file = argv[i];
		}
		else if (!u_k_file)
		{
			u_k_file = argv[i];
		}
		else
		{
			die(usage);
		}


	if( !pub_file || !in_file || !rvk_file || !u_k_file)
		die(usage);

	if( !out_file )
	{
		out_file = g_strdup_printf("%s.proxy", in_file);
	}
}

int
main( int argc, char** argv )
{
	int i;
	bswabe_pub_t* pub;
	bswabe_cph_t* cph;
	bswabe_point* rvk;

	element_t lambda_k;
	GByteArray* cph_buf;
	GByteArray* l_k;

	int file_len;

	FILE* fp_u_k;

	parse_args(argc, argv);

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	read_cph_file(in_file, &cph_buf);

	cph = bswabe_cph_unserialize(pub, cph_buf, 1, 0); //

	rvk = bswabe_point_unserialize(pub, suck_file(rvk_file), 1);

	element_t* lambda_i_ps = bswabe_convert(pub, rvk);

	fp_u_k = fopen_read_or_die( u_k_file);
	fscanf(fp_u_k, "%s", u_k_str);

	convert(pub, cph, rvk, u_k_str, lambda_k, lambda_i_ps);

	int proxy_key_size = 0;

	for(i=0; i<REVOKE_T; i++)
		proxy_key_size += element_length_in_bytes(lambda_i_ps[i]);

	cph_buf = bswabe_cph_serialize(cph, 1); // 1 for proxy

	write_cph_file(out_file, cph_buf);

	l_k = g_byte_array_new();

	serialize_element(l_k, lambda_k);

	spit_file(lambda_file , l_k, 1);

	g_byte_array_free(cph_buf, 1);

	element_clear(lambda_k);

	for(i=0; i<REVOKE_T; i++)
		element_clear(lambda_i_ps[i]);

	fclose(fp_u_k);

	if (!keep)
		unlink(in_file);

	return 0;
}
