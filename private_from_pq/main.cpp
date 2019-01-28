#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int main(int argc, char *argv[])
{
	BUF_MEM* mem = NULL;
	BUF_MEM* rsa_mem = NULL;
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *p1 = BN_new();
	BIGNUM *q1 = BN_new();
	BIGNUM *dmp1 = BN_new();
	BIGNUM *dmq1 = BN_new();
	BIGNUM *iqmp = BN_new();
	BIGNUM *phi = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	RSA *key = RSA_new();
	BIO* bio = BIO_new(BIO_s_mem());
	BIO* rsa_bio = BIO_new(BIO_s_mem());

	if (argc < 3)
	{
		printf("usage: %s p q\n", argv[0]);
		
		return 1;
	}

	if (!(BN_hex2bn(&p, argv[1])) || !(BN_hex2bn(&q, argv[2]))) {
		printf("usage: %s p q\n", argv[0]);

		return 1;
	}

	if (!(BN_is_prime_ex(p, BN_prime_checks, ctx, NULL)) ||
		!(BN_is_prime_ex(q, BN_prime_checks, ctx, NULL))) {

		printf("Arguments must both be prime!\n");

		return 1;
	}

	BN_dec2bn(&e, "65537");

	/* Calculate RSA private key parameters */

	/* n = p*q */
	BN_mul(n, p, q, ctx);
	/* p1 = p-1 */
	BN_sub(p1, p, BN_value_one());
	/* q1 = q-1 */
	BN_sub(q1, q, BN_value_one());
	/* phi(pq) = (p-1)*(q-1) */
	BN_mul(phi, p1, q1, ctx);
	/* d = e^-1 mod phi */
	BN_mod_inverse(d, e, phi, ctx);
	/* dmp1 = d mod (p-1) */
	BN_mod(dmp1, d, p1, ctx);
	/* dmq1 = d mod (q-1) */
	BN_mod(dmq1, d, q1, ctx);
	/* iqmp = q^-1 mod p */
	BN_mod_inverse(iqmp, q, p, ctx);

	RSA_set0_key(key, n, e, d);
	RSA_set0_factors(key, p, q);
	RSA_set0_crt_params(key, dmp1, dmq1, iqmp);

	RSA_print(bio, key, 0);

	BIO_get_mem_ptr(bio, &mem);

	PEM_write_bio_RSAPrivateKey(rsa_bio, key, NULL, NULL, 0, 0, NULL);

	BIO_get_mem_ptr(rsa_bio, &rsa_mem);

	printf(mem->data);
	printf(rsa_mem->data);

	FILE* rsapem = NULL;

	fopen_s(&rsapem, "privatekey.pem", "wb+");

	if (rsapem) {

		fwrite(rsa_mem->data, sizeof(char), rsa_mem->length, rsapem);
		fclose(rsapem);
	}


	/* Release allocated objects */
	BN_CTX_free(ctx);
	RSA_free(key); /* also frees n, e, d, p, q, dmp1, dmq1, iqmp */
	BN_clear_free(phi);
	BN_clear_free(p1);
	BN_clear_free(q1);
	BIO_free(bio);
	BIO_free(rsa_bio);

	return 0;
}

