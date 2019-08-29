/*
 * File:   gen_policy.c
 * Author: sjahid2
 *
 * Created on June 15, 2010, 1:08 AM
 */
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include <assert.h>

#include <openssl/sha.h>
#include <glib.h>
#include <pbc.h>


int leaf_count = 0;
int leaf_total = 0;

GPtrArray* internals;
char policy_str[2000];

typedef struct
{
    int k;
    int internal;
    char* attr;
    GPtrArray* children;
}
bswabe_policy_t;

bswabe_policy_t*
base_node( int k, char* s )
{
	bswabe_policy_t* p;

	p = (bswabe_policy_t*) malloc(sizeof(bswabe_policy_t));
	p->k = k;
        p->internal = s ? -1 : 1; //-1 for leaf, 1 for internal
	p->attr = s ? strdup(s) : 0;
	p->children = g_ptr_array_new();

	return p;
}

void
gen_policy()
{
    int leaf_or_int;
    int int_index;
    int i;

    srand ( time(NULL) );
    
    while(leaf_count != leaf_total)
    {
        bswabe_policy_t* node;

        int_index = rand() % internals->len;
        bswabe_policy_t* parent = g_ptr_array_index(internals, int_index);

        leaf_or_int= rand() % 10 + 1;

        if(leaf_or_int < 9)
        {
            leaf_count++;
            char s[10];
            sprintf(s, "attr%d", leaf_count);
            node = base_node(0, s);
            g_ptr_array_add(parent->children, node);
            (parent->k)++;
        }
        else
        {
            node = base_node(0, 0);
            g_ptr_array_add(internals, node);
            g_ptr_array_add(parent->children, node);
        }

    }
  
}

void
print_policy(bswabe_policy_t* root)
{
    int i;
    char str[100] = "\0";
   
    if(root->attr == 0)
    {
        int threshold = rand() % root->children->len + 1 ;
        sprintf(str, "%d of ( ", threshold);
        strcat(policy_str, str);

        for(i=0; i<root->children->len; i++ )
        {
            print_policy(root->children->pdata[i]);

            if(i < (root->children->len-1))
            {
                strcat(policy_str, ", ");
            }
        }
        sprintf(str, ")");
        strcat(policy_str, str);
    }
    else
    {
        if(root->attr)
        {
            sprintf(str, "%s", root->attr);
            strcat(policy_str, str);
        }
    }
}
void
policy_free( bswabe_policy_t* p)
{
	int i;

	if( p->attr )
	{
		free(p->attr);
	}

	for( i = 0; i < p->children->len; i++ )
            policy_free(g_ptr_array_index(p->children, i));

	g_ptr_array_free(p->children, 1);

	free(p);
}
void
shred_policy(bswabe_policy_t* root)
{
    int i;

    
    for(i=0; i<root->children->len; i++)
    {
        bswabe_policy_t* child;

        if(i>=0 && i < root->children->len)
            child = g_ptr_array_index(root->children, i);

        if(child->attr == 0)
        {
            shred_policy(child);
            if(child->internal == 0)
            {
                if(child->children->len == 0)
                {
                    g_ptr_array_remove(root->children, child);
                    i--;
                    policy_free(child);
                }

                else if(child->children->len == 1)
                {
                    g_ptr_array_add(root->children, child->children->pdata[0]);
                    g_ptr_array_remove(root->children, child);
                    i--;
                }
            }
        }
    }
    if(root->children->len <= 1)
    {
        g_ptr_array_remove(internals, root);
        root->internal = 0;
    }
}

int main(int argc, char** argv) {

    if(argc!=2)
    {
        exit(1);
    }
    sscanf(argv[1], "%d", &leaf_total);
    internals = g_ptr_array_new();

    bswabe_policy_t* root = base_node(0, 0);
    g_ptr_array_add(internals, root);

    gen_policy();
    shred_policy(root);
    print_policy(root);

    printf("%s\n", policy_str);
    
    policy_free(root);

    g_ptr_array_free(internals, 1);
    
    return (EXIT_SUCCESS);
}