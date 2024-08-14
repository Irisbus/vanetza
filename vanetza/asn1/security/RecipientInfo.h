/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE1609dot2"
 * 	found in "asn1/IEEE1609dot2.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security_ -R`
 */

#ifndef	_Vanetza_Security_RecipientInfo_H_
#define	_Vanetza_Security_RecipientInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PreSharedKeyRecipientInfo.h"
#include "SymmRecipientInfo.h"
#include "PKRecipientInfo.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Vanetza_Security_RecipientInfo_PR {
	Vanetza_Security_RecipientInfo_PR_NOTHING,	/* No components present */
	Vanetza_Security_RecipientInfo_PR_pskRecipInfo,
	Vanetza_Security_RecipientInfo_PR_symmRecipInfo,
	Vanetza_Security_RecipientInfo_PR_certRecipInfo,
	Vanetza_Security_RecipientInfo_PR_signedDataRecipInfo,
	Vanetza_Security_RecipientInfo_PR_rekRecipInfo
} Vanetza_Security_RecipientInfo_PR;

/* Vanetza_Security_RecipientInfo */
typedef struct Vanetza_Security_RecipientInfo {
	Vanetza_Security_RecipientInfo_PR present;
	union Vanetza_Security_RecipientInfo_u {
		Vanetza_Security_PreSharedKeyRecipientInfo_t	 pskRecipInfo;
		Vanetza_Security_SymmRecipientInfo_t	 symmRecipInfo;
		Vanetza_Security_PKRecipientInfo_t	 certRecipInfo;
		Vanetza_Security_PKRecipientInfo_t	 signedDataRecipInfo;
		Vanetza_Security_PKRecipientInfo_t	 rekRecipInfo;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security_RecipientInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security_RecipientInfo;
extern asn_CHOICE_specifics_t asn_SPC_Vanetza_Security_RecipientInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security_RecipientInfo_1[5];
extern asn_per_constraints_t asn_PER_type_Vanetza_Security_RecipientInfo_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_Security_RecipientInfo_H_ */
#include "asn_internal.h"
