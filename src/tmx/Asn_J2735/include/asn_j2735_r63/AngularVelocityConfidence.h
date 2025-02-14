/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SDSM"
 * 	found in "J2735_201603_2023-06-22.asn"
 * 	`asn1c -fcompound-names `
 */

#ifndef	_AngularVelocityConfidence_H_
#define	_AngularVelocityConfidence_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PitchRateConfidence.h"
#include "RollRateConfidence.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AngularVelocityConfidence */
typedef struct AngularVelocityConfidence {
	PitchRateConfidence_t	*pitchRateConfidence	/* OPTIONAL */;
	RollRateConfidence_t	*rollRateConfidence	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AngularVelocityConfidence_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AngularVelocityConfidence;
extern asn_SEQUENCE_specifics_t asn_SPC_AngularVelocityConfidence_specs_1;
extern asn_TYPE_member_t asn_MBR_AngularVelocityConfidence_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _AngularVelocityConfidence_H_ */
#include <asn_internal.h>
