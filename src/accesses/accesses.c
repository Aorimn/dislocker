/* -*- coding: utf-8 -*- */
/* -*- mode: c -*- */
/*
 * Dislocker -- enables to read/write on BitLocker encrypted partitions under
 * Linux
 * Copyright (C) 2012-2013  Romain Coltel, Hervé Schauer Consultants
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */


#include "dislocker/dislocker.priv.h"
#include "dislocker/accesses/accesses.h"
#include "dislocker/accesses/bek/bekfile.h"
#include "dislocker/accesses/rp/recovery_password.h"
#include "dislocker/accesses/user_pass/user_pass.h"

#include "dislocker/metadata/vmk.h"
#include "dislocker/metadata/fvek.h"
#include "dislocker/metadata/datums.h"

#include "dislocker/return_values.h"


int dis_get_access(dis_context_t dis_ctx)
{
	void* vmk_datum = NULL;
	void* fvek_datum = NULL;

	datum_key_t* fvek_typed_datum = NULL;


	/*
	 * First, get the VMK datum using either any necessary mean
	 */
	while(dis_ctx->cfg.decryption_mean)
	{
		if(dis_ctx->cfg.decryption_mean & DIS_USE_CLEAR_KEY)
		{
			if(!get_vmk_from_clearkey(dis_ctx->metadata, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~DIS_USE_CLEAR_KEY;
			}
			else
			{
				dis_printf(L_INFO, "Used clear key decryption method\n");
				dis_ctx->cfg.decryption_mean = DIS_USE_CLEAR_KEY;
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & DIS_USE_USER_PASSWORD)
		{
			if(!get_vmk_from_user_pass(dis_ctx->metadata, &dis_ctx->cfg, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~DIS_USE_USER_PASSWORD;
			}
			else
			{
				dis_printf(L_INFO, "Used user password decryption method\n");
				dis_ctx->cfg.decryption_mean = DIS_USE_USER_PASSWORD;

				/* We don't need the user password anymore */
				if(dis_ctx->cfg.user_password)
				{
					memclean(
						(char*) dis_ctx->cfg.user_password,
						strlen((char*) dis_ctx->cfg.user_password)
					);
					dis_ctx->cfg.user_password = NULL;
				}
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & DIS_USE_RECOVERY_PASSWORD)
		{
			if(!get_vmk_from_rp(dis_ctx->metadata, &dis_ctx->cfg, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~DIS_USE_RECOVERY_PASSWORD;
			}
			else
			{
				dis_printf(L_INFO, "Used recovery password decryption method\n");
				dis_ctx->cfg.decryption_mean = DIS_USE_RECOVERY_PASSWORD;

				/* We don't need the recovery_password anymore */
				if(dis_ctx->cfg.recovery_password)
				{
					memclean(
						(char*) dis_ctx->cfg.recovery_password,
						strlen((char*) dis_ctx->cfg.recovery_password)
					);
					dis_ctx->cfg.recovery_password = NULL;
				}
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & DIS_USE_BEKFILE)
		{
			if(!get_vmk_from_bekfile(dis_ctx->metadata, &dis_ctx->cfg, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~DIS_USE_BEKFILE;
			}
			else
			{
				dis_printf(L_INFO, "Used bek file decryption method\n");
				dis_ctx->cfg.decryption_mean = DIS_USE_BEKFILE;
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & DIS_USE_FVEKFILE)
		{
			if(!build_fvek_from_file(&dis_ctx->cfg, &fvek_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~DIS_USE_FVEKFILE;
			}
			else
			{
				dis_printf(L_INFO, "Used FVEK file decryption method\n");
				dis_ctx->cfg.decryption_mean = DIS_USE_FVEKFILE;
				break;
			}
		}
		else if(dis_ctx->cfg.decryption_mean & DIS_USE_VMKFILE)
		{
			if(!get_vmk_from_file(&dis_ctx->cfg, &vmk_datum))
			{
				dis_ctx->cfg.decryption_mean &= (unsigned) ~DIS_USE_VMKFILE;
			}
			else
			{
				dis_printf(L_INFO, "Used VMK file decryption method\n");
				dis_ctx->cfg.decryption_mean = DIS_USE_VMKFILE;
				break;
			}
		}
		else
		{
			dis_printf(L_CRITICAL, "Wtf!? Abort.\n");
			return DIS_RET_ERROR_VMK_RETRIEVAL;
		}
	}

	if(!dis_ctx->cfg.decryption_mean)
	{
		dis_printf(
			L_CRITICAL,
			"None of the provided decryption mean is "
			"decrypting the keys. Abort.\n"
		);
		return DIS_RET_ERROR_VMK_RETRIEVAL;
	}

	dis_ctx->io_data.vmk = vmk_datum;

	checkupdate_dis_state(dis_ctx, DIS_STATE_AFTER_VMK);


	/*
	 * NOTE -- We could here validate the information buffer in a more precise
	 * way using the VMK and the validations structure (the one after the
	 * information one, see bitlocker_validations_t in metadata/metadata.h)
	 */


	/*
	 * And then, use the VMK to decrypt the FVEK
	 */
	if(dis_ctx->cfg.decryption_mean != DIS_USE_FVEKFILE)
	{
		if(!get_fvek(dis_ctx->metadata, vmk_datum, &fvek_datum))
			return DIS_RET_ERROR_FVEK_RETRIEVAL;
	}


	/* Just a check of the algo used to crypt data here */
	fvek_typed_datum = (datum_key_t*) fvek_datum;
	fvek_typed_datum->algo &= 0xffff;

	if(fvek_typed_datum->algo < DIS_CIPHER_LOWEST_SUPPORTED ||
	   fvek_typed_datum->algo > DIS_CIPHER_HIGHEST_SUPPORTED)
	{
		dis_printf(
			L_CRITICAL,
			"Can't recognize the encryption algorithm used: %#hx. Abort\n",
			fvek_typed_datum->algo
		);
		return DIS_RET_ERROR_CRYPTO_ALGORITHM_UNSUPPORTED;
	}

	dis_ctx->io_data.fvek = fvek_typed_datum;

	checkupdate_dis_state(dis_ctx, DIS_STATE_AFTER_FVEK);

	return DIS_RET_SUCCESS;
}


#ifdef _HAVE_RUBY
struct _rb_dis_access {
	dis_metadata_t metadata;

	datum_vmk_t* vmk;
	datum_aes_ccm_t* fvek;
};
typedef struct _rb_dis_access* rb_dis_access_t;


static inline VALUE save_ret_vmk(rb_dis_access_t dis_accesses, void* vmk_datum)
{
	extern VALUE dis_rb_classes[DIS_RB_CLASS_MAX];
	datum_header_safe_t header;

	if(get_header_safe(vmk_datum, &header) != TRUE)
		rb_raise(rb_eRuntimeError, "Cannot get VMK header safely");

	dis_accesses->vmk = vmk_datum;

	VALUE datum = rb_str_new((char*) vmk_datum, (long) header.datum_size);

	/* Transform the VMK in a VALUE to be returned */
	return rb_cDislockerMetadataDatum_new(
		dis_rb_classes[DIS_RB_CLASS_DATUM],
		datum
	);
}


static VALUE rb_get_vmk_from_clearkey(VALUE self)
{
	void* vmk_datum              = NULL;
	rb_dis_access_t dis_accesses = DATA_PTR(self);

	/* Get the VMK */
	if(!get_vmk_from_clearkey(dis_accesses->metadata, &vmk_datum))
		rb_raise(rb_eRuntimeError, "Couldn't retrieve the VMK");

	/* Save it */
	return save_ret_vmk(dis_accesses, vmk_datum);
}

static VALUE rb_get_vmk_from_userpass(VALUE self, VALUE rb_userpass)
{
	void* vmk_datum              = NULL;
	uint8_t* userpass            = NULL;
	rb_dis_access_t dis_accesses = DATA_PTR(self);

	Check_Type(rb_userpass, T_STRING);
	userpass = (uint8_t*) StringValuePtr(rb_userpass);

	/* Get the VMK */
	if(!get_vmk_from_user_pass2(dis_accesses->metadata, &userpass, &vmk_datum))
		rb_raise(rb_eRuntimeError, "Couldn't retrieve the VMK");

	/* Save it */
	return save_ret_vmk(dis_accesses, vmk_datum);
}

static VALUE rb_get_vmk_from_rp(VALUE self, VALUE rb_rp)
{
	void* vmk_datum              = NULL;
	uint8_t* rp                  = NULL;
	rb_dis_access_t dis_accesses = DATA_PTR(self);

	Check_Type(rb_rp, T_STRING);
	rp = (uint8_t*) StringValuePtr(rb_rp);

	/* Get the VMK */
	if(!get_vmk_from_rp2(dis_accesses->metadata, rp, &vmk_datum))
		rb_raise(rb_eRuntimeError, "Couldn't retrieve the VMK");

	/* Save it */
	return save_ret_vmk(dis_accesses, vmk_datum);
}

static VALUE rb_get_vmk_from_bekfile(VALUE self, VALUE rb_bekfile_path)
{
	void* vmk_datum              = NULL;
	char* bekfile_path           = NULL;
	rb_dis_access_t dis_accesses = DATA_PTR(self);

	Check_Type(rb_bekfile_path, T_STRING);
	bekfile_path = StringValuePtr(rb_bekfile_path);

	/* Get the VMK */
	if(!get_vmk_from_bekfile2(dis_accesses->metadata, bekfile_path, &vmk_datum))
		rb_raise(rb_eRuntimeError, "Couldn't retrieve the VMK");

	/* Save it */
	return save_ret_vmk(dis_accesses, vmk_datum);
}

static VALUE rb_get_fvek(int argc, VALUE *argv, VALUE self)
{
	datum_vmk_t* vmk_datum       = NULL;
	void* fvek_datum             = NULL;
	rb_dis_access_t dis_accesses = DATA_PTR(self);
	datum_header_safe_t header;
	extern VALUE dis_rb_classes[DIS_RB_CLASS_MAX];

	if(argc == 0)
	{
		if(dis_accesses->vmk == NULL)
			rb_raise(rb_eRuntimeError, "Didn't retrieve the VMK and none given");

		vmk_datum = dis_accesses->vmk;
	}
	else
	{
		Data_Get_Struct(
			argv[0],
			datum_vmk_t,
			vmk_datum
		);
	}

	/* Get the FVEK */
	if(!get_fvek(dis_accesses->metadata, vmk_datum, &fvek_datum))
		rb_raise(rb_eRuntimeError, "Could not retrieve the FVEK");

	/* Save it */
	dis_accesses->fvek = fvek_datum;

	if(get_header_safe(vmk_datum, &header) != TRUE)
		rb_raise(rb_eRuntimeError, "Cannot get VMK header safely");

	/* Transform the FVEK in a VALUE to be returned */
	return rb_cDislockerMetadataDatum_new(
		dis_rb_classes[DIS_RB_CLASS_DATUM],
		rb_str_new(fvek_datum, header.datum_size)
	);
}



static void rb_cDislockerAccesses_free(rb_dis_access_t dis_accesses)
{
	if(dis_accesses)
		dis_free(dis_accesses);
}

static VALUE rb_cDislockerAccesses_alloc(VALUE klass)
{
	rb_dis_access_t dis_accesses = NULL;

	return Data_Wrap_Struct(
		klass,
		NULL,
		rb_cDislockerAccesses_free,
		dis_accesses
	);
}

static VALUE rb_cDislockerAccesses_init(VALUE self, VALUE rb_dis_meta)
{
	rb_dis_access_t dis_accesses = dis_malloc(sizeof(struct _rb_dis_access));

	Data_Get_Struct(
		rb_dis_meta,
		struct _dis_metadata,
		dis_accesses->metadata
	);

	dis_accesses->vmk  = NULL;
	dis_accesses->fvek = NULL;

	DATA_PTR(self) = dis_accesses;

	return Qnil;
}

void Init_accesses(VALUE rb_mDislocker)
{
	VALUE rb_cDislockerAccesses = rb_define_class_under(
		rb_mDislocker,
		"Accesses",
		rb_cObject
	);
	extern VALUE dis_rb_classes[DIS_RB_CLASS_MAX];
	dis_rb_classes[DIS_RB_CLASS_ACCESSES] = rb_cDislockerAccesses;

	rb_define_alloc_func(rb_cDislockerAccesses, rb_cDislockerAccesses_alloc);
	rb_define_method(
		rb_cDislockerAccesses,
		"initialize",
		rb_cDislockerAccesses_init,
		1
	);

	rb_define_method(
		rb_cDislockerAccesses,
		"vmk_from_clearkey",
		rb_get_vmk_from_clearkey,
		0
	);
	rb_define_method(
		rb_cDislockerAccesses,
		"vmk_from_userpass",
		rb_get_vmk_from_userpass,
		1
	);
	rb_define_method(
		rb_cDislockerAccesses,
		"vmk_from_recoverypassword",
		rb_get_vmk_from_rp,
		1
	);
	rb_define_method(
		rb_cDislockerAccesses,
		"vmk_from_bekfile",
		rb_get_vmk_from_bekfile,
		1
	);
	rb_define_method(
		rb_cDislockerAccesses,
		"fvek",
		rb_get_fvek,
		-1
	);
}
#endif /* _HAVE_RUBY */
