#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"

char* usage =
		"Usage: easier-enc [OPTION ...] PUB_KEY IN_FILE [POLICY]\n"
		"\n"
		"Encrypt IN_FILE under the decryption policy POLICY using public key\n"
		"PUB_KEY. The encrypted file will be written to IN_FILE.cpabe and IN_FILE.cpaes unless\n"
		"the -o option is used. The original file will be removed. If POLICY\n"
		"is not specified, the policy will be read from stdin.\n"
		"\n"
		"Mandatory arguments to long options are mandatory for short options too.\n\n"
		" -h, --help               print this message\n\n"
		" -k, --keep-input-file    don't delete original file\n\n"
		" -v, --version            print version information\n\n"		
		" -o, --output FILE        write resulting key to FILE.cpabe FILE.cpaes\n\n"
		" -d, --deterministic      use deterministic \"random\" numbers\n"
		"                          (only for debugging)\n\n"
		"";

char* pub_file = 0;
char* in_file  = 0;
char* out_file = 0;
char* aes_file = 0;
int   keep     = 0;

char* policy = 0;

void
parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
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
			printf(CPABE_VERSION, "-enc");
			exit(0);
		}	
		else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
		{
			if( ++i >= argc )
				die(usage);
			else
			{
				out_file = g_strdup_printf("%s.cpabe", argv[i]);
				aes_file = g_strdup_printf("%s.cpaes", argv[i]);
			}
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
		else if( !policy )
		{
			policy = parse_policy_lang(argv[i]);
		}
		else
			die(usage);

	if( !pub_file || !in_file )
		die(usage);

	if( !out_file )
	{
		out_file = g_strdup_printf("%s.cpabe", in_file);
		aes_file = g_strdup_printf("%s.cpaes", in_file);
	}

	if( !policy )
		policy = parse_policy_lang(suck_stdin());
}

int
main( int argc, char** argv )
{
	bswabe_pub_t* pub;
	bswabe_cph_t* cph;
	int file_len;
	GByteArray* plt;
	GByteArray* cph_buf;
	GByteArray* aes_buf;
	element_t m;

	parse_args(argc, argv);

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

	if( !(cph = bswabe_enc(pub, m, policy)) )
		die("%s", bswabe_error());

	free(policy);

	cph_buf = bswabe_cph_serialize(cph, 0);
	bswabe_cph_free(cph, 0);

	plt = suck_file(in_file);
	file_len = plt->len;

	aes_buf = aes_128_cbc_encrypt(plt, m);
	g_byte_array_free(plt, 1);
	element_clear(m);

	write_aes_file(aes_file, file_len, aes_buf);
	write_cph_file(out_file, cph_buf);

	g_byte_array_free(cph_buf, 1);
	g_byte_array_free(aes_buf, 1);

	if( !keep )
		unlink(in_file);

	return 0;
}
