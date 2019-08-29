#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"

char* usage =
		"Usage: easier-keygen PUB_KEY MASTER_KEY ATTR [ATTR ...]\n"
		"\n"
		"Generate a key with the listed attributes using public key PUB_KEY and\n"
		"master secret key MASTER_KEY. Output will be written to the file\n"
		"\"priv_key\" and priv_key.id unless the -o option is specified.\n"
		"\n"
		"Attributes come in two forms: non-numerical and numerical. Non-numerical\n"
		"attributes are simply any string of letters, digits, and underscores\n"
		"beginning with a letter.\n"
		"\n"
		"Numerical attributes are specified as `attr = N', where N is a non-negative\n"
		"integer less than 2^64 and `attr' is another string. The whitespace around\n"
		"the `=' is optional. One may specify an explicit length of k bits for the\n"
		"integer by giving `attr = N#k'. Note that any comparisons in a policy given\n"
		"to easier-enc(1) must then specify the same number of bits, e.g.,\n"
		"`attr > 5#12'.\n"
		"\n"
		"The keywords `and', `or', and `of', are reserved for the policy language\n"
		"of cpabe-enc (1) and may not be used for either type of attribute.\n"
		"\n"
		"Mandatory arguments to long options are mandatory for short options too.\n\n"
		" -h, --help               print this message\n\n"
		" -v, --version            print version information\n\n"
		" -o, --output FILE        write resulting key to FILE and ID to FILE.id \n\n"
		" -d, --deterministic      use deterministic \"random\" numbers\n"
		"                          (only for debugging)\n\n"
		"";

/*
	TODO ensure we don't give out the same attribute more than once (esp
	as different numerical values)
 */

char*  out_file = "priv_key";
char*  pub_file = 0;
char*  msk_file = 0;
char*  id_file_name = 0;		
char** attrs    = 0;
element_t u_k ;

gint
comp_string( gconstpointer a, gconstpointer b)
{
	return strcmp(a, b);
}

void
parse_args( int argc, char** argv )
{
	int i;
	GSList* alist;
	GSList* ap;
	int n;

	alist = 0;
	for( i = 1; i < argc; i++ )
		if( !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-keygen");
			exit(0);
		}		
		else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
		{
			if( ++i >= argc )
				die(usage);
			else
			{
				out_file = argv[i];
				id_file_name = g_strdup_printf("%s.id", argv[i]);
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
		else if( !msk_file )
		{
			msk_file = argv[i];
		}
		else
		{
			parse_attribute(&alist, argv[i]);
		}

	if( !pub_file || !msk_file || !alist )
		die(usage);
	
	if(!id_file_name)
	{
		id_file_name = g_strdup_printf("%s.id", out_file);
	}

	alist = g_slist_sort(alist, comp_string);
	n = g_slist_length(alist);

	attrs = malloc((n + 1) * sizeof(char*));

	i = 0;
	for( ap = alist; ap; ap = ap->next )
		attrs[i++] = ap->data;
	attrs[i] = 0;
}

int
main( int argc, char** argv )
{
	bswabe_pub_t* pub;
	bswabe_msk_t* msk;
	bswabe_prv_t* prv;

	FILE* fp_users;

	parse_args(argc, argv);

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	msk = bswabe_msk_unserialize(pub, suck_file(msk_file), 1);

	prv = bswabe_keygen(pub, msk, attrs, u_k);

	spit_file(out_file, bswabe_prv_serialize(prv), 1);

	/*file containing friend CPABE ID*/
	fp_users = fopen_write_or_die(id_file_name);
	if(fp_users)
	{
		element_fprintf(fp_users, "%B\n", u_k);
		fclose(fp_users);
	}

	element_clear(u_k);
	return 0;
}
