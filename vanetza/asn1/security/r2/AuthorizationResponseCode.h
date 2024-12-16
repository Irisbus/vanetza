/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EtsiTs102941TypesAuthorization"
 * 	found in "asn1/release2/TS102941v221/TypesAuthorization.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security2_ -R`
 */

#ifndef	_Vanetza_Security2_AuthorizationResponseCode_H_
#define	_Vanetza_Security2_AuthorizationResponseCode_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeEnumerated.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Vanetza_Security2_AuthorizationResponseCode {
	Vanetza_Security2_AuthorizationResponseCode_ok	= 0,
	Vanetza_Security2_AuthorizationResponseCode_its_aa_cantparse	= 1,
	Vanetza_Security2_AuthorizationResponseCode_its_aa_badcontenttype	= 2,
	Vanetza_Security2_AuthorizationResponseCode_its_aa_imnottherecipient	= 3,
	Vanetza_Security2_AuthorizationResponseCode_its_aa_unknownencryptionalgorithm	= 4,
	Vanetza_Security2_AuthorizationResponseCode_its_aa_decryptionfailed	= 5,
	Vanetza_Security2_AuthorizationResponseCode_its_aa_keysdontmatch	= 6,
	Vanetza_Security2_AuthorizationResponseCode_its_aa_incompleterequest	= 7,
	Vanetza_Security2_AuthorizationResponseCode_its_aa_invalidencryptionkey	= 8,
	Vanetza_Security2_AuthorizationResponseCode_its_aa_outofsyncrequest	= 9,
	Vanetza_Security2_AuthorizationResponseCode_its_aa_unknownea	= 10,
	Vanetza_Security2_AuthorizationResponseCode_its_aa_invalidea	= 11,
	Vanetza_Security2_AuthorizationResponseCode_its_aa_deniedpermissions	= 12,
	Vanetza_Security2_AuthorizationResponseCode_aa_ea_cantreachea	= 13,
	Vanetza_Security2_AuthorizationResponseCode_ea_aa_cantparse	= 14,
	Vanetza_Security2_AuthorizationResponseCode_ea_aa_badcontenttype	= 15,
	Vanetza_Security2_AuthorizationResponseCode_ea_aa_imnottherecipient	= 16,
	Vanetza_Security2_AuthorizationResponseCode_ea_aa_unknownencryptionalgorithm	= 17,
	Vanetza_Security2_AuthorizationResponseCode_ea_aa_decryptionfailed	= 18,
	Vanetza_Security2_AuthorizationResponseCode_invalidaa	= 19,
	Vanetza_Security2_AuthorizationResponseCode_invalidaasignature	= 20,
	Vanetza_Security2_AuthorizationResponseCode_wrongea	= 21,
	Vanetza_Security2_AuthorizationResponseCode_unknownits	= 22,
	Vanetza_Security2_AuthorizationResponseCode_invalidsignature	= 23,
	Vanetza_Security2_AuthorizationResponseCode_invalidencryptionkey	= 24,
	Vanetza_Security2_AuthorizationResponseCode_deniedpermissions	= 25,
	Vanetza_Security2_AuthorizationResponseCode_deniedtoomanycerts	= 26
	/*
	 * Enumeration is extensible
	 */
} e_Vanetza_Security2_AuthorizationResponseCode;

/* Vanetza_Security2_AuthorizationResponseCode */
typedef long	 Vanetza_Security2_AuthorizationResponseCode_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_Vanetza_Security2_AuthorizationResponseCode_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security2_AuthorizationResponseCode;
extern const asn_INTEGER_specifics_t asn_SPC_Vanetza_Security2_AuthorizationResponseCode_specs_1;
asn_struct_free_f Vanetza_Security2_AuthorizationResponseCode_free;
asn_struct_print_f Vanetza_Security2_AuthorizationResponseCode_print;
asn_constr_check_f Vanetza_Security2_AuthorizationResponseCode_constraint;
ber_type_decoder_f Vanetza_Security2_AuthorizationResponseCode_decode_ber;
der_type_encoder_f Vanetza_Security2_AuthorizationResponseCode_encode_der;
xer_type_decoder_f Vanetza_Security2_AuthorizationResponseCode_decode_xer;
xer_type_encoder_f Vanetza_Security2_AuthorizationResponseCode_encode_xer;
jer_type_encoder_f Vanetza_Security2_AuthorizationResponseCode_encode_jer;
oer_type_decoder_f Vanetza_Security2_AuthorizationResponseCode_decode_oer;
oer_type_encoder_f Vanetza_Security2_AuthorizationResponseCode_encode_oer;
per_type_decoder_f Vanetza_Security2_AuthorizationResponseCode_decode_uper;
per_type_encoder_f Vanetza_Security2_AuthorizationResponseCode_encode_uper;
per_type_decoder_f Vanetza_Security2_AuthorizationResponseCode_decode_aper;
per_type_encoder_f Vanetza_Security2_AuthorizationResponseCode_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_Security2_AuthorizationResponseCode_H_ */
#include "asn_internal.h"
