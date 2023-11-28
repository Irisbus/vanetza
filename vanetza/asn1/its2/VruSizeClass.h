/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/TS102894-2v221-CDD.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_VruSizeClass_H_
#define	_VruSizeClass_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeInteger.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum VruSizeClass {
	VruSizeClass_unavailable	= 0,
	VruSizeClass_low	= 1,
	VruSizeClass_medium	= 2,
	VruSizeClass_high	= 3
} e_VruSizeClass;

/* VruSizeClass */
typedef long	 VruSizeClass_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_VruSizeClass;
asn_struct_free_f VruSizeClass_free;
asn_struct_print_f VruSizeClass_print;
asn_constr_check_f VruSizeClass_constraint;
ber_type_decoder_f VruSizeClass_decode_ber;
der_type_encoder_f VruSizeClass_encode_der;
xer_type_decoder_f VruSizeClass_decode_xer;
xer_type_encoder_f VruSizeClass_encode_xer;
jer_type_encoder_f VruSizeClass_encode_jer;
oer_type_decoder_f VruSizeClass_decode_oer;
oer_type_encoder_f VruSizeClass_encode_oer;
per_type_decoder_f VruSizeClass_decode_uper;
per_type_encoder_f VruSizeClass_encode_uper;
per_type_decoder_f VruSizeClass_decode_aper;
per_type_encoder_f VruSizeClass_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _VruSizeClass_H_ */
#include "asn_internal.h"
