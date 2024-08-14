/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE1609dot2BaseTypes"
 * 	found in "asn1/IEEE1609dot2BaseTypes.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security_ -R`
 */

#ifndef	_Vanetza_Security_PolygonalRegion_H_
#define	_Vanetza_Security_PolygonalRegion_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Vanetza_Security_TwoDLocation;

/* Vanetza_Security_PolygonalRegion */
typedef struct Vanetza_Security_PolygonalRegion {
	A_SEQUENCE_OF(struct Vanetza_Security_TwoDLocation) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security_PolygonalRegion_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security_PolygonalRegion;
extern asn_SET_OF_specifics_t asn_SPC_Vanetza_Security_PolygonalRegion_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security_PolygonalRegion_1[1];
extern asn_per_constraints_t asn_PER_type_Vanetza_Security_PolygonalRegion_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "TwoDLocation.h"

#endif	/* _Vanetza_Security_PolygonalRegion_H_ */
#include "asn_internal.h"
