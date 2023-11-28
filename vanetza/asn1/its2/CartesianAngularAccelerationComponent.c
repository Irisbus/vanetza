/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/TS102894-2v221-CDD.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#include "CartesianAngularAccelerationComponent.h"

static asn_TYPE_member_t asn_MBR_CartesianAngularAccelerationComponent_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CartesianAngularAccelerationComponent, value),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CartesianAngularAccelerationComponentValue,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"value"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CartesianAngularAccelerationComponent, confidence),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AngularAccelerationConfidence,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"confidence"
		},
};
static const ber_tlv_tag_t asn_DEF_CartesianAngularAccelerationComponent_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CartesianAngularAccelerationComponent_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* value */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* confidence */
};
static asn_SEQUENCE_specifics_t asn_SPC_CartesianAngularAccelerationComponent_specs_1 = {
	sizeof(struct CartesianAngularAccelerationComponent),
	offsetof(struct CartesianAngularAccelerationComponent, _asn_ctx),
	asn_MAP_CartesianAngularAccelerationComponent_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_CartesianAngularAccelerationComponent = {
	"CartesianAngularAccelerationComponent",
	"CartesianAngularAccelerationComponent",
	&asn_OP_SEQUENCE,
	asn_DEF_CartesianAngularAccelerationComponent_tags_1,
	sizeof(asn_DEF_CartesianAngularAccelerationComponent_tags_1)
		/sizeof(asn_DEF_CartesianAngularAccelerationComponent_tags_1[0]), /* 1 */
	asn_DEF_CartesianAngularAccelerationComponent_tags_1,	/* Same as above */
	sizeof(asn_DEF_CartesianAngularAccelerationComponent_tags_1)
		/sizeof(asn_DEF_CartesianAngularAccelerationComponent_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_CartesianAngularAccelerationComponent_1,
	2,	/* Elements count */
	&asn_SPC_CartesianAngularAccelerationComponent_specs_1	/* Additional specs */
};

