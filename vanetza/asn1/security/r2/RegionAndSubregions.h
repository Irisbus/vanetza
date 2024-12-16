/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Ieee1609Dot2BaseTypes"
 * 	found in "build.asn1/ieee/IEEE1609dot2BaseTypes.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security2_ -R`
 */

#ifndef	_Vanetza_Security2_RegionAndSubregions_H_
#define	_Vanetza_Security2_RegionAndSubregions_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Uint8.h"
#include "SequenceOfUint16.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Vanetza_Security2_RegionAndSubregions */
typedef struct Vanetza_Security2_RegionAndSubregions {
	Vanetza_Security2_Uint8_t	 region;
	Vanetza_Security2_SequenceOfUint16_t	 subregions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security2_RegionAndSubregions_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security2_RegionAndSubregions;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_Security2_RegionAndSubregions_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security2_RegionAndSubregions_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_Security2_RegionAndSubregions_H_ */
#include "asn_internal.h"
