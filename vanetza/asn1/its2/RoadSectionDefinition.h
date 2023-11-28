/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/TS102894-2v221-CDD.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_RoadSectionDefinition_H_
#define	_RoadSectionDefinition_H_


#include "asn_application.h"

/* Including external dependencies */
#include "GeoPosition.h"
#include "StandardLength2B.h"
#include "PathReferences.h"
#include "BOOLEAN.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct GeoPosition;

/* RoadSectionDefinition */
typedef struct RoadSectionDefinition {
	GeoPosition_t	 startingPointSection;
	StandardLength2B_t	*lengthOfSection;	/* OPTIONAL */
	struct GeoPosition	*endingPointSection;	/* OPTIONAL */
	PathReferences_t	 connectedPaths;
	PathReferences_t	 includedPaths;
	BOOLEAN_t	 isEventZoneIncluded;
	BOOLEAN_t	 isEventZoneConnected;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RoadSectionDefinition_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RoadSectionDefinition;
extern asn_SEQUENCE_specifics_t asn_SPC_RoadSectionDefinition_specs_1;
extern asn_TYPE_member_t asn_MBR_RoadSectionDefinition_1[7];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "GeoPosition.h"

#endif	/* _RoadSectionDefinition_H_ */
#include "asn_internal.h"
