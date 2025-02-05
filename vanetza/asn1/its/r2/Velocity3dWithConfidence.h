/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/release2/TS102894-2v221-CDD.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_ITS2_ -R`
 */

#ifndef	_Vanetza_ITS2_Velocity3dWithConfidence_H_
#define	_Vanetza_ITS2_Velocity3dWithConfidence_H_


#include "asn_application.h"

/* Including external dependencies */
#include "VelocityPolarWithZ.h"
#include "VelocityCartesian.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Vanetza_ITS2_Velocity3dWithConfidence_PR {
	Vanetza_ITS2_Velocity3dWithConfidence_PR_NOTHING,	/* No components present */
	Vanetza_ITS2_Velocity3dWithConfidence_PR_polarVelocity,
	Vanetza_ITS2_Velocity3dWithConfidence_PR_cartesianVelocity
} Vanetza_ITS2_Velocity3dWithConfidence_PR;

/* Vanetza_ITS2_Velocity3dWithConfidence */
typedef struct Vanetza_ITS2_Velocity3dWithConfidence {
	Vanetza_ITS2_Velocity3dWithConfidence_PR present;
	union Vanetza_ITS2_Velocity3dWithConfidence_u {
		Vanetza_ITS2_VelocityPolarWithZ_t	 polarVelocity;
		Vanetza_ITS2_VelocityCartesian_t	 cartesianVelocity;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_ITS2_Velocity3dWithConfidence_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_ITS2_Velocity3dWithConfidence;
extern asn_CHOICE_specifics_t asn_SPC_Vanetza_ITS2_Velocity3dWithConfidence_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_ITS2_Velocity3dWithConfidence_1[2];
extern asn_per_constraints_t asn_PER_type_Vanetza_ITS2_Velocity3dWithConfidence_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_ITS2_Velocity3dWithConfidence_H_ */
#include "asn_internal.h"
