#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <assert.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// gcc -g -c -o test-ecdsa.o test-ecdsa.c && gcc -o test-ecdsa-befor test-ecdsa.o -Lopenssl-before/install/lib/ -lcrypto -ldl
// taskset --cpu-list 0 ./ecdsa-ecdsa-befor
static __inline__ unsigned long rdtsc(void)
{
  unsigned int hi, lo;
  __asm__ __volatile__ ("xorl %%eax, %%eax; cpuid; rdtsc" : "=a"(lo), "=d"(hi) : : "ebx", "ecx");
  return ( (unsigned long)lo)|( ((unsigned long)hi)<<32 );
}

/*
    NID_sect163k1 is the NIST Binary-Curve K-163
    NID_sect163r2 is the NIST Binary-Curve B-163
*/
int main(int argc, char** argv) {
    int ret;
    ECDSA_SIG* sig;
    EC_KEY* eckey = EC_KEY_new();
    long long before, after;
    BN_CTX* ctx = NULL;
    BIGNUM* order;
    BIGNUM* m;
    const EC_GROUP* group;
    BIGNUM* x;
    BIGNUM* y;
    const EC_POINT* pubkey;


    char digest[20];
    char test_string[10];
    int i;

    char* bn_dec;

    FILE* theoutputfile = fdopen(1, "w");

    if ((ctx=BN_CTX_new()) == NULL) goto err;

    //eckey = EC_KEY_new_by_curve_name(NID_sect163k1);
    eckey = EC_KEY_new_by_curve_name(NID_sect163r2);
    if (eckey == NULL)
        goto err;

    // Generate a public/private key pair
    if (!EC_KEY_generate_key(eckey)) goto err;
    
    order = BN_new();
    if (!order) goto err;

    group = EC_KEY_get0_group(eckey);
    if (!EC_GROUP_get_order(group, order, ctx)) goto err;

    /* Print out the public key too, to be sure & verify */
    x = BN_new(); y = BN_new();
    if (!x || !y) goto err;

    pubkey = EC_KEY_get0_public_key(eckey);
    if (!EC_POINT_get_affine_coordinates_GF2m(group, pubkey, x, y, ctx)) goto err; 

    FILE* publickey = fopen("publickey", "w");
    bn_dec = BN_bn2dec(x);
    fprintf(publickey, "%s,", bn_dec);
    free(bn_dec);
    bn_dec = BN_bn2dec(y);
    fprintf(publickey, "%s\n", bn_dec);
    free(bn_dec);
    fclose(publickey);

    /* Print out the private key */
    FILE* privatekey = fopen("privatekey", "w");
    bn_dec = BN_bn2dec(EC_KEY_get0_private_key(eckey));
    fprintf(privatekey, "%s\n", bn_dec);
    free(bn_dec);
    fclose(privatekey);
    
    m = BN_new();
    if (!m) goto err;

    for (i = 0; i < 10000; i++) {
        // Digest a 'random' string to sign with SHA-1
        int len = snprintf(test_string, 10, "%i", i);
        SHA1(test_string, len, digest);

        // Compute a ECDSA signature of a SHA-1 hash value using ECDSA_do_sign, time how long it takes
        before = rdtsc();
        sig = ECDSA_do_sign(digest, 20, eckey);
        after = rdtsc();

        if (sig == NULL) {
            goto err;
        }
        
        BN_bin2bn(digest, 20, m);
        
        bn_dec = BN_bn2dec(m);
        fprintf(theoutputfile, "%s,", bn_dec);
        free(bn_dec);


        // We could verify the signature if we wanted (result should be _1_ for a correct result)
        // ret = ECDSA_do_verify(digest, 20, sig, eckey);
        bn_dec = BN_bn2dec(sig->r);
        fprintf(theoutputfile, "%s,", bn_dec);
        free(bn_dec);

        bn_dec = BN_bn2dec(sig->s);
        fprintf(theoutputfile, "%s,", bn_dec);
        free(bn_dec);

        fprintf(theoutputfile, "%lld\n", after - before);
    }


    // We're done
err:
    ERR_print_errors_fp(stderr);

    if (eckey) EC_KEY_free(eckey);

    return 0;
}
