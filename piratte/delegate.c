#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"

/*B delegates any attribute to C from the private key that s/he received from A */
char* usage =
		"Usage: easier-delegate [OPTION ...] PUB_KEY_B MASTER_KEY_B PRIV_KEY_B ID_FILE_C ATTR [ATTRS] \n"
		"\n"
		"B delagtes attributes to C using his public key PUB_KEY_B, master key MASTER_KEY_B,\n"
		"private key PRIV_KEY_B (B got from A), "
		"C's ID file (B generated while keygen to C - usually filename is C's private_key.id),\n"
		"\n"
		"Mandatory arguments to long options are mandatory for short options too.\n\n"
		" -h, --help               print this message\n\n"
		" -v, --version            print version information\n\n"
		" -o, --output FILE        write output to FILE\n\n"
		"";


char* pub_file = 0;
char* msk_file = 0;
char* prv_file = 0;
char** attrs = 0;
char* out_file = "del_key";
char* u_k_file = 0;
char u_k_str[100];

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
			printf(CPABE_VERSION, "-delegate");
			exit(0);
		}
		else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
		{
			if( ++i >= argc )
				die(usage);
			else
				out_file = argv[i];
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !msk_file )
		{
			msk_file = argv[i];
		}		
		else if( !prv_file )
		{
			prv_file = argv[i];
		}
		else if(!u_k_file)
		{
			u_k_file = argv[i];
		}
		else
		{
			parse_attribute(&alist, argv[i]);
		}

	if(!out_file || !pub_file || !msk_file || !prv_file || !u_k_file)
		die(usage);

	alist = g_slist_sort(alist, comp_string);
	n = g_slist_length(alist);

	attrs = malloc((n + 1) * sizeof(char*));

	i = 0;
	for( ap = alist; ap; ap = ap->next )
	{
		attrs[i] = ap->data;
		i++;
	}
	attrs[i] = 0;
}

int
main( int argc, char** argv )
{
	bswabe_pub_t* pub;
	bswabe_msk_t* msk;
	bswabe_prv_t* prv;
	bswabe_del_prv_t* del_prv;
	FILE* fp_u_k;

	parse_args(argc, argv);

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	msk = bswabe_msk_unserialize(pub, suck_file(msk_file), 1);
	prv = bswabe_prv_unserialize(pub, suck_file(prv_file), 1);

	fp_u_k = fopen_read_or_die( u_k_file);
	fscanf(fp_u_k, "%s", u_k_str);

	del_prv = bswabe_delegate(pub, msk, prv, u_k_str, attrs);

	spit_file(out_file, bswabe_del_prv_serialize(del_prv), 1);

	if(fp_u_k)
		fclose(fp_u_k);

	return 0;
}
