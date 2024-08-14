/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE1609dot2BaseTypes"
 * 	found in "asn1/IEEE1609dot2BaseTypes.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security_ -R`
 */

#ifndef	_Vanetza_Security_IdentifiedRegion_H_
#define	_Vanetza_Security_IdentifiedRegion_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CountryOnly.h"
#include "CountryAndRegions.h"
#include "CountryAndSubregions.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Vanetza_Security_IdentifiedRegion_PR {
	Vanetza_Security_IdentifiedRegion_PR_NOTHING,	/* No components present */
	Vanetza_Security_IdentifiedRegion_PR_countryOnly,
	Vanetza_Security_IdentifiedRegion_PR_countryAndRegions,
	Vanetza_Security_IdentifiedRegion_PR_countryAndSubregions
	/* Extensions may appear below */
	
} Vanetza_Security_IdentifiedRegion_PR;

/* Vanetza_Security_IdentifiedRegion */
typedef struct Vanetza_Security_IdentifiedRegion {
	Vanetza_Security_IdentifiedRegion_PR present;
	union Vanetza_Security_IdentifiedRegion_u {
		Vanetza_Security_CountryOnly_t	 countryOnly;
		Vanetza_Security_CountryAndRegions_t	 countryAndRegions;
		Vanetza_Security_CountryAndSubregions_t	 countryAndSubregions;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security_IdentifiedRegion_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security_IdentifiedRegion;
extern asn_CHOICE_specifics_t asn_SPC_Vanetza_Security_IdentifiedRegion_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security_IdentifiedRegion_1[3];
extern asn_per_constraints_t asn_PER_type_Vanetza_Security_IdentifiedRegion_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_Security_IdentifiedRegion_H_ */
#include "asn_internal.h"
