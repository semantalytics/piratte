#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "common.h"
#include "bswabe.h"
#include "policy_lang.h"

char* usage =
		"Usage: easier-revoke [OPTION ...] PUB_KEY MASTER_KEY [user_1 user_2 ... user_t]\n"
		"\n"
		"Revoke user_1 ... user_t using public key PUB_KEY and master key MASTER_KEY.\n"
		"Output (proxy key) will be written to the file \"prx_key\"\n"
		"unless the --output option is used.\n"
		"Leave the user list empty when no or less than t users are revoked\n"
		"Mandatory arguments to long options are mandatory for short options too.\n\n"
		" -h, --help               	print this message\n\n"
		" -v, --version            	print version information\n\n"		
		" -o, --output 	PROXY_KEY  	write proxy key to PROXY_KEY\n\n"
		" -d, --deterministic      	use deterministic \"random\" numbers\n"
		"                          	(only for debugging)\n\n"
		"";

char* pub_file = 0;
char* msk_file = 0;
char* out_file = "prx_key";

int
parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
		if( !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-revoke");
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
			break;
		}
	if( !pub_file )
		die(usage);
	else if(!msk_file)
		die(usage);
	else if(!out_file)
		die(usage);

	return i;
}

int
main( int argc, char** argv )
{
	bswabe_pub_t* pub;
	bswabe_msk_t* msk;
	bswabe_point* revoke_list;
	char** rl = 0;
	FILE* fp;
	
	int i = 0, j = 0;

	i = parse_args(argc, argv);

	if((argc-i) > REVOKE_T)
	{
		die("Trying to revoke %d users. Can revoke at most %d users.\n", (argc-i), REVOKE_T);
	}

	int n = argc - i;
	
	rl = malloc((n + 1) * sizeof(char *));
	for(j=0; j<n; j++, i++)
	{
		fp = fopen_read_or_die(argv[i]);
		rl[j] = malloc(50);
		fscanf(fp, "%s", rl[j]);
		fclose(fp);
	}
	rl[j] = 0;
		
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	msk = bswabe_msk_unserialize(pub, suck_file(msk_file), 1);

	revoke_list = bswabe_revoke(pub, msk, rl, (n));

	spit_file(out_file, bswabe_point_serialize(revoke_list), 1);

	return 0;
}
