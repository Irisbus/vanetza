/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/TS102894-2v221-CDD.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_ActionID_H_
#define	_ActionID_H_


#include "asn_application.h"

/* Including external dependencies */
#include "StationID.h"
#include "SequenceNumber.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ActionID */
typedef struct ActionID {
	StationID_t	 originatingStationId;
	SequenceNumber_t	 sequenceNumber;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ActionID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ActionID;

#ifdef __cplusplus
}
#endif

#endif	/* _ActionID_H_ */
#include "asn_internal.h"
