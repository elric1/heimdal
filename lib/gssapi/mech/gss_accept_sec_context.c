/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libgssapi/gss_accept_sec_context.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

/*
 * We are "collecting" if gc_target_len != 0.
 * We try to avoid calloc/memcpy.
 * We free in delete_sec_context() as well as between iterations
 * as we may have multiple rounds...
 */

static OM_uint32
collect_token(struct _gss_context *ctx, gss_buffer_t input_token)
{
	unsigned char *p = input_token->value;
	size_t len = input_token->length;
	gss_buffer_t gci;
	size_t l;

	/*
	 * Token must start with [APPLICATION 0] SEQUENCE.
	 * But if it doesn't assume it is DCE-STYLE Kerberos!
	 * We simply consume the tag for now...
	 */
	if (!ctx->gc_target_len) {
		free(ctx->gc_free_this);
		ctx->gc_free_this = NULL;
		_mg_buffer_zero(&ctx->gc_input);

		/*
		 * Let's prepare gc_input for the case where
		 * we aren't collecting.
		 */

		ctx->gc_input.length = len;
		ctx->gc_input.value  = p;

		if (len == 0)
			return GSS_S_COMPLETE;

		/*
		 * XXXrcd: is this a valid assumption?
		 * NTLM starts w/ "NTLMSSP\0" and thus
		 * the first byte is N == 0x4e != 0x60.
		 * I'll keep looking at this.
		 */
		if (*p != 0x60)
			return GSS_S_COMPLETE;

		if (der_get_length(p+1, len-1, &ctx->gc_target_len, &l) != 0)
			return GSS_S_DEFECTIVE_TOKEN;

		ctx->gc_oid_offset  = l + 1;
		ctx->gc_target_len += ctx->gc_oid_offset;

		if (ctx->gc_target_len == ASN1_INDEFINITE ||
		    ctx->gc_target_len < len)
			return GSS_S_DEFECTIVE_TOKEN;

		/* We've got it all, short-circuit the collection */
		if (ctx->gc_target_len == len)
			goto done;

		ctx->gc_input.length = 0;
		ctx->gc_input.value  = calloc(ctx->gc_target_len, 1);
		if (!ctx->gc_input.value)
			return GSS_S_FAILURE;
		ctx->gc_free_this = ctx->gc_input.value;
	}

	if (len == 0)
		return GSS_S_DEFECTIVE_TOKEN;

	gci = &ctx->gc_input;

	if (ctx->gc_target_len > gci->length) {
		if (gci->length + len > ctx->gc_target_len) {
			// XXXrcd: free ctx->gc_input;
			return GSS_S_DEFECTIVE_TOKEN;
		}
		memcpy((char *)gci->value + gci->length, p, len);
		gci->length += len;
	}

	if (gci->length != ctx->gc_target_len) {
		return GSS_S_CONTINUE_NEEDED;
	}

done:
	ctx->gc_target_len = 0;

	return GSS_S_COMPLETE;
}

static gss_OID_desc krb5_mechanism =
    {9, rk_UNCONST("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02")};
static gss_OID_desc ntlm_mechanism =
    {10, rk_UNCONST("\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a")};
static gss_OID_desc spnego_mechanism =
    {6, rk_UNCONST("\x2b\x06\x01\x05\x05\x02")};

static OM_uint32
choose_mech(struct _gss_context *ctx)
{
	gss_OID_desc	 mech;
	gss_OID		 mech_oid;
	unsigned char	*p = ctx->gc_input.value;
	size_t		 len = ctx->gc_input.length;

	if (len == 0) {
		/*
		 * There is the a wierd mode of SPNEGO (in CIFS and
		 * SASL GSS-SPENGO where the first token is zero
		 * length and the acceptor returns a mech_list, lets
		 * hope that is what is happening now.
		 *
		 * http://msdn.microsoft.com/en-us/library/cc213114.aspx
		 * "NegTokenInit2 Variation for Server-Initiation"
		 */
		mech_oid = &spnego_mechanism;
		goto gss_get_mechanism;
	}

	p   += ctx->gc_oid_offset;
	len -= ctx->gc_oid_offset;

	/*
	 * Decode the OID for the mechanism. Simplify life by
	 * assuming that the OID length is less than 128 bytes.
	 */
	if (len < 2 || *p != 0x06)
		goto bail;
	if ((p[1] & 0x80) || p[1] > (len - 2))
		goto bail;
	mech.length = p[1];
	p += 2;
	len -= 2;
	mech.elements = p;
	mech_oid = &mech;

bail:
	if (ctx->gc_input.length > 8 &&
	    memcmp((const char *)ctx->gc_input.value, "NTLMSSP\x00", 8) == 0)
	{
		mech_oid = &ntlm_mechanism;
		goto gss_get_mechanism;
	} else if (ctx->gc_input.length != 0 &&
		   ((const char *)ctx->gc_input.value)[0] == 0x6E)
	{
		/* Could be a raw AP-REQ (check for APPLICATION tag) */
		mech_oid = &krb5_mechanism;
		goto gss_get_mechanism;
	}

gss_get_mechanism:
	/*
	 * If mech_oid == GSS_C_NO_OID then the mech is non-standard
	 * and we have to try all mechs (that we have a cred element
	 * for, if we have a cred).
	 */
	if (mech_oid != GSS_C_NO_OID) {
		ctx->gc_mech = __gss_get_mechanism(mech_oid);
		if (!ctx->gc_mech) {
			return (GSS_S_BAD_MECH);
		}
		return GSS_S_COMPLETE;
	}

	return GSS_S_COMPLETE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_accept_sec_context(OM_uint32 *minor_status,
    gss_ctx_id_t *context_handle,
    gss_const_cred_id_t acceptor_cred_handle,
    const gss_buffer_t input_token,
    const gss_channel_bindings_t input_chan_bindings,
    gss_name_t *src_name,
    gss_OID *mech_type,
    gss_buffer_t output_token,
    OM_uint32 *ret_flags,
    OM_uint32 *time_rec,
    gss_cred_id_t *delegated_cred_handle)
{
	OM_uint32 major_status, mech_ret_flags, junk;
	gssapi_mech_interface m;
	struct _gss_context *ctx = (struct _gss_context *) *context_handle;
	struct _gss_cred *cred = (struct _gss_cred *) acceptor_cred_handle;
	struct _gss_mechanism_cred *mc;
	gss_const_cred_id_t acceptor_mc;
	gss_cred_id_t delegated_mc = GSS_C_NO_CREDENTIAL;
	gss_name_t src_mn = GSS_C_NO_NAME;
	gss_OID mech_ret_type = GSS_C_NO_OID;
	int initial;

	*minor_status = 0;
	if (src_name)
	    *src_name = GSS_C_NO_NAME;
	if (mech_type)
	    *mech_type = GSS_C_NO_OID;
	if (ret_flags)
	    *ret_flags = 0;
	if (time_rec)
	    *time_rec = 0;
	if (delegated_cred_handle)
	    *delegated_cred_handle = GSS_C_NO_CREDENTIAL;
	_mg_buffer_zero(output_token);

	if (!*context_handle) {
		ctx = calloc(sizeof(*ctx), 1);
		if (!ctx) {
			*minor_status = ENOMEM;
			return (GSS_S_DEFECTIVE_TOKEN);
		}
		*context_handle = (gss_ctx_id_t)ctx;
		ctx->gc_initial = 1;
	}

	major_status = collect_token(ctx, input_token);
	if (major_status == GSS_S_CONTINUE_NEEDED)
		return major_status;

	/* If we get here, then we have a complete token */

	initial = ctx->gc_initial;
	ctx->gc_initial = 0;

	if (major_status == GSS_S_COMPLETE && initial) {
		major_status = choose_mech(ctx);
		if (major_status != GSS_S_COMPLETE)
			return major_status;
	}
	m = ctx->gc_mech;

	if (cred) {
		HEIM_SLIST_FOREACH(mc, &cred->gc_mc, gmc_link)
			if (mc->gmc_mech == m)
				break;
		if (!mc) {
		        gss_delete_sec_context(&junk, context_handle, NULL);
			return (GSS_S_BAD_MECH);
		}
		acceptor_mc = mc->gmc_cred;
	} else {
		acceptor_mc = GSS_C_NO_CREDENTIAL;
	}
	delegated_mc = GSS_C_NO_CREDENTIAL;

	mech_ret_flags = 0;
	major_status = m->gm_accept_sec_context(minor_status,
	    &ctx->gc_ctx,
	    acceptor_mc,
	    &ctx->gc_input,
	    input_chan_bindings,
	    &src_mn,
	    &mech_ret_type,
	    output_token,
	    &mech_ret_flags,
	    time_rec,
	    &delegated_mc);
	if (major_status != GSS_S_COMPLETE &&
	    major_status != GSS_S_CONTINUE_NEEDED)
	{
		_gss_mg_error(m, major_status, *minor_status);
		gss_delete_sec_context(&junk, context_handle, NULL);
		return (major_status);
	}

	if (mech_type)
	    *mech_type = mech_ret_type;

	if (src_name && src_mn) {
		/*
		 * Make a new name and mark it as an MN.
		 */
		struct _gss_name *name = _gss_make_name(m, src_mn);

		if (!name) {
			m->gm_release_name(minor_status, &src_mn);
		        gss_delete_sec_context(&junk, context_handle, NULL);
			return (GSS_S_FAILURE);
		}
		*src_name = (gss_name_t) name;
	} else if (src_mn) {
		m->gm_release_name(minor_status, &src_mn);
	}

	if (mech_ret_flags & GSS_C_DELEG_FLAG) {
		if (!delegated_cred_handle) {
			m->gm_release_cred(minor_status, &delegated_mc);
			mech_ret_flags &=
			    ~(GSS_C_DELEG_FLAG|GSS_C_DELEG_POLICY_FLAG);
		} else if (gss_oid_equal(mech_ret_type, &m->gm_mech_oid) == 0) {
			/*
			 * If the returned mech_type is not the same
			 * as the mech, assume its pseudo mech type
			 * and the returned type is already a
			 * mech-glue object
			 */
			*delegated_cred_handle = delegated_mc;

		} else if (delegated_mc) {
			struct _gss_cred *dcred;
			struct _gss_mechanism_cred *dmc;

			dcred = malloc(sizeof(struct _gss_cred));
			if (!dcred) {
				*minor_status = ENOMEM;
				gss_delete_sec_context(&junk, context_handle, NULL);
				return (GSS_S_FAILURE);
			}
			HEIM_SLIST_INIT(&dcred->gc_mc);
			dmc = malloc(sizeof(struct _gss_mechanism_cred));
			if (!dmc) {
				free(dcred);
				*minor_status = ENOMEM;
				gss_delete_sec_context(&junk, context_handle, NULL);
				return (GSS_S_FAILURE);
			}
			dmc->gmc_mech = m;
			dmc->gmc_mech_oid = &m->gm_mech_oid;
			dmc->gmc_cred = delegated_mc;
			HEIM_SLIST_INSERT_HEAD(&dcred->gc_mc, dmc, gmc_link);

			*delegated_cred_handle = (gss_cred_id_t) dcred;
		}
	}

	if (ret_flags)
	    *ret_flags = mech_ret_flags;
	return (major_status);
}
