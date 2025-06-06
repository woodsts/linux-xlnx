// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2021 IBM Corporation
 */

#include <linux/module.h>
#include <crypto/internal/akcipher.h>
#include <crypto/internal/ecc.h>
#include <crypto/akcipher.h>
#include <crypto/ecdh.h>
#include <crypto/ecdsa.h>
#include <linux/asn1_decoder.h>
#include <linux/scatterlist.h>

#include "ecdsasignature.asn1.h"

struct ecc_ctx {
	unsigned int curve_id;
	const struct ecc_curve *curve;

	bool pub_key_set;
	u64 x[ECC_MAX_DIGITS]; /* pub key x and y coordinates */
	u64 y[ECC_MAX_DIGITS];
	struct ecc_point pub_key;
};

/*
 * Get the r and s components of a signature from the X509 certificate.
 */
int ecdsa_get_signature_rs(u64 *dest, size_t hdrlen, unsigned char tag,
			   const void *value, size_t vlen, unsigned int ndigits)
{
	size_t bufsize = ndigits * sizeof(u64);
	ssize_t diff = vlen - bufsize;
	const char *d = value;

	if (!value || !vlen)
		return -EINVAL;

	/* diff = 0: 'value' has exacly the right size
	 * diff > 0: 'value' has too many bytes; one leading zero is allowed that
	 *           makes the value a positive integer; error on more
	 * diff < 0: 'value' is missing leading zeros
	 */
	if (diff > 0) {
		/* skip over leading zeros that make 'value' a positive int */
		if (*d == 0) {
			vlen -= 1;
			diff--;
			d++;
		}
		if (diff)
			return -EINVAL;
	}
	if (-diff >= bufsize)
		return -EINVAL;

	ecc_digits_from_bytes(d, vlen, dest, ndigits);

	return 0;
}
EXPORT_SYMBOL(ecdsa_get_signature_rs);

int ecdsa_get_signature_r(void *context, size_t hdrlen, unsigned char tag,
			  const void *value, size_t vlen)
{
	struct ecdsa_signature_ctx *sig = context;

	return ecdsa_get_signature_rs(sig->r, hdrlen, tag, value, vlen,
				      sig->curve->g.ndigits);
}

int ecdsa_get_signature_s(void *context, size_t hdrlen, unsigned char tag,
			  const void *value, size_t vlen)
{
	struct ecdsa_signature_ctx *sig = context;

	return ecdsa_get_signature_rs(sig->s, hdrlen, tag, value, vlen,
				      sig->curve->g.ndigits);
}

static int _ecdsa_verify(struct ecc_ctx *ctx, const u64 *hash, const u64 *r, const u64 *s)
{
	const struct ecc_curve *curve = ctx->curve;
	unsigned int ndigits = curve->g.ndigits;
	u64 s1[ECC_MAX_DIGITS];
	u64 u1[ECC_MAX_DIGITS];
	u64 u2[ECC_MAX_DIGITS];
	u64 x1[ECC_MAX_DIGITS];
	u64 y1[ECC_MAX_DIGITS];
	struct ecc_point res = ECC_POINT_INIT(x1, y1, ndigits);

	/* 0 < r < n  and 0 < s < n */
	if (vli_is_zero(r, ndigits) || vli_cmp(r, curve->n, ndigits) >= 0 ||
	    vli_is_zero(s, ndigits) || vli_cmp(s, curve->n, ndigits) >= 0)
		return -EBADMSG;

	/* hash is given */
	pr_devel("hash : %016llx %016llx ... %016llx\n",
		 hash[ndigits - 1], hash[ndigits - 2], hash[0]);

	/* s1 = (s^-1) mod n */
	vli_mod_inv(s1, s, curve->n, ndigits);
	/* u1 = (hash * s1) mod n */
	vli_mod_mult_slow(u1, hash, s1, curve->n, ndigits);
	/* u2 = (r * s1) mod n */
	vli_mod_mult_slow(u2, r, s1, curve->n, ndigits);
	/* res = u1*G + u2 * pub_key */
	ecc_point_mult_shamir(&res, u1, &curve->g, u2, &ctx->pub_key, curve);

	/* res.x = res.x mod n (if res.x > order) */
	if (unlikely(vli_cmp(res.x, curve->n, ndigits) == 1))
		/* faster alternative for NIST p521, p384, p256 & p192 */
		vli_sub(res.x, res.x, curve->n, ndigits);

	if (!vli_cmp(res.x, r, ndigits))
		return 0;

	return -EKEYREJECTED;
}

/*
 * Verify an ECDSA signature.
 */
static int ecdsa_verify(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);
	size_t bufsize = ctx->curve->g.ndigits * sizeof(u64);
	struct ecdsa_signature_ctx sig_ctx = {
		.curve = ctx->curve,
	};
	u64 hash[ECC_MAX_DIGITS];
	unsigned char *buffer;
	int ret;

	if (unlikely(!ctx->pub_key_set))
		return -EINVAL;

	buffer = kmalloc(req->src_len + req->dst_len, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	sg_pcopy_to_buffer(req->src,
		sg_nents_for_len(req->src, req->src_len + req->dst_len),
		buffer, req->src_len + req->dst_len, 0);

	ret = asn1_ber_decoder(&ecdsasignature_decoder, &sig_ctx,
			       buffer, req->src_len);
	if (ret < 0)
		goto error;

	if (bufsize > req->dst_len)
		bufsize = req->dst_len;

	ecc_digits_from_bytes(buffer + req->src_len, bufsize,
			      hash, ctx->curve->g.ndigits);

	ret = _ecdsa_verify(ctx, hash, sig_ctx.r, sig_ctx.s);

error:
	kfree(buffer);

	return ret;
}

static int ecdsa_ecc_ctx_init(struct ecc_ctx *ctx, unsigned int curve_id)
{
	ctx->curve_id = curve_id;
	ctx->curve = ecc_get_curve(curve_id);
	if (!ctx->curve)
		return -EINVAL;

	return 0;
}


static void ecdsa_ecc_ctx_deinit(struct ecc_ctx *ctx)
{
	ctx->pub_key_set = false;
}

static int ecdsa_ecc_ctx_reset(struct ecc_ctx *ctx)
{
	unsigned int curve_id = ctx->curve_id;
	int ret;

	ecdsa_ecc_ctx_deinit(ctx);
	ret = ecdsa_ecc_ctx_init(ctx, curve_id);
	if (ret == 0)
		ctx->pub_key = ECC_POINT_INIT(ctx->x, ctx->y,
					      ctx->curve->g.ndigits);
	return ret;
}

/*
 * Set the public ECC key as defined by RFC5480 section 2.2 "Subject Public
 * Key". Only the uncompressed format is supported.
 */
static int ecdsa_set_pub_key(struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);
	unsigned int digitlen, ndigits;
	const unsigned char *d = key;
	int ret;

	ret = ecdsa_ecc_ctx_reset(ctx);
	if (ret < 0)
		return ret;

	if (keylen < 1 || ((keylen - 1) & 1) != 0)
		return -EINVAL;
	/* we only accept uncompressed format indicated by '4' */
	if (d[0] != 4)
		return -EINVAL;

	keylen--;
	digitlen = keylen >> 1;

	ndigits = DIV_ROUND_UP(digitlen, sizeof(u64));
	if (ndigits != ctx->curve->g.ndigits)
		return -EINVAL;

	d++;

	ecc_digits_from_bytes(d, digitlen, ctx->pub_key.x, ndigits);
	ecc_digits_from_bytes(&d[digitlen], digitlen, ctx->pub_key.y, ndigits);

	ret = ecc_is_pubkey_valid_full(ctx->curve, &ctx->pub_key);

	ctx->pub_key_set = ret == 0;

	return ret;
}

static void ecdsa_exit_tfm(struct crypto_akcipher *tfm)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);

	ecdsa_ecc_ctx_deinit(ctx);
}

static unsigned int ecdsa_max_size(struct crypto_akcipher *tfm)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);

	return DIV_ROUND_UP(ctx->curve->nbits, 8);
}

static int ecdsa_nist_p521_init_tfm(struct crypto_akcipher *tfm)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);

	return ecdsa_ecc_ctx_init(ctx, ECC_CURVE_NIST_P521);
}

static struct akcipher_alg ecdsa_nist_p521 = {
	.verify = ecdsa_verify,
	.set_pub_key = ecdsa_set_pub_key,
	.max_size = ecdsa_max_size,
	.init = ecdsa_nist_p521_init_tfm,
	.exit = ecdsa_exit_tfm,
	.base = {
		.cra_name = "ecdsa-nist-p521",
		.cra_driver_name = "ecdsa-nist-p521-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct ecc_ctx),
	},
};

static int ecdsa_nist_p384_init_tfm(struct crypto_akcipher *tfm)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);

	return ecdsa_ecc_ctx_init(ctx, ECC_CURVE_NIST_P384);
}

static struct akcipher_alg ecdsa_nist_p384 = {
	.verify = ecdsa_verify,
	.set_pub_key = ecdsa_set_pub_key,
	.max_size = ecdsa_max_size,
	.init = ecdsa_nist_p384_init_tfm,
	.exit = ecdsa_exit_tfm,
	.base = {
		.cra_name = "ecdsa-nist-p384",
		.cra_driver_name = "ecdsa-nist-p384-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct ecc_ctx),
	},
};

static int ecdsa_nist_p256_init_tfm(struct crypto_akcipher *tfm)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);

	return ecdsa_ecc_ctx_init(ctx, ECC_CURVE_NIST_P256);
}

static struct akcipher_alg ecdsa_nist_p256 = {
	.verify = ecdsa_verify,
	.set_pub_key = ecdsa_set_pub_key,
	.max_size = ecdsa_max_size,
	.init = ecdsa_nist_p256_init_tfm,
	.exit = ecdsa_exit_tfm,
	.base = {
		.cra_name = "ecdsa-nist-p256",
		.cra_driver_name = "ecdsa-nist-p256-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct ecc_ctx),
	},
};

static int ecdsa_nist_p192_init_tfm(struct crypto_akcipher *tfm)
{
	struct ecc_ctx *ctx = akcipher_tfm_ctx(tfm);

	return ecdsa_ecc_ctx_init(ctx, ECC_CURVE_NIST_P192);
}

static struct akcipher_alg ecdsa_nist_p192 = {
	.verify = ecdsa_verify,
	.set_pub_key = ecdsa_set_pub_key,
	.max_size = ecdsa_max_size,
	.init = ecdsa_nist_p192_init_tfm,
	.exit = ecdsa_exit_tfm,
	.base = {
		.cra_name = "ecdsa-nist-p192",
		.cra_driver_name = "ecdsa-nist-p192-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct ecc_ctx),
	},
};
static bool ecdsa_nist_p192_registered;

static int __init ecdsa_init(void)
{
	int ret;

	/* NIST p192 may not be available in FIPS mode */
	ret = crypto_register_akcipher(&ecdsa_nist_p192);
	ecdsa_nist_p192_registered = ret == 0;

	ret = crypto_register_akcipher(&ecdsa_nist_p256);
	if (ret)
		goto nist_p256_error;

	ret = crypto_register_akcipher(&ecdsa_nist_p384);
	if (ret)
		goto nist_p384_error;

	ret = crypto_register_akcipher(&ecdsa_nist_p521);
	if (ret)
		goto nist_p521_error;

	return 0;

nist_p521_error:
	crypto_unregister_akcipher(&ecdsa_nist_p384);

nist_p384_error:
	crypto_unregister_akcipher(&ecdsa_nist_p256);

nist_p256_error:
	if (ecdsa_nist_p192_registered)
		crypto_unregister_akcipher(&ecdsa_nist_p192);
	return ret;
}

static void __exit ecdsa_exit(void)
{
	if (ecdsa_nist_p192_registered)
		crypto_unregister_akcipher(&ecdsa_nist_p192);
	crypto_unregister_akcipher(&ecdsa_nist_p256);
	crypto_unregister_akcipher(&ecdsa_nist_p384);
	crypto_unregister_akcipher(&ecdsa_nist_p521);
}

subsys_initcall(ecdsa_init);
module_exit(ecdsa_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stefan Berger <stefanb@linux.ibm.com>");
MODULE_DESCRIPTION("ECDSA generic algorithm");
MODULE_ALIAS_CRYPTO("ecdsa-nist-p192");
MODULE_ALIAS_CRYPTO("ecdsa-nist-p256");
MODULE_ALIAS_CRYPTO("ecdsa-nist-p384");
MODULE_ALIAS_CRYPTO("ecdsa-nist-p521");
MODULE_ALIAS_CRYPTO("ecdsa-generic");
