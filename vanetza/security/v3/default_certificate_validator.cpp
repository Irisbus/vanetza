#include <vanetza/security/v3/default_certificate_validator.hpp>


namespace vanetza
{
namespace security
{
namespace v3
{

DefaultCertificateValidator::DefaultCertificateValidator(Backend& backend, CertificateCache& cache, const TrustStore& trust_store) :
    m_backend(backend),
    m_cert_cache(cache),
    m_trust_store(trust_store)
{
}

bool check_time_consistency(const Certificate& certificate, const Certificate& signer)
{
    StartAndEndValidity certificate_time = certificate.get_start_and_end_validity();
    StartAndEndValidity signer_time = signer.get_start_and_end_validity();

    if (signer_time.start_validity > certificate_time.start_validity) {
        return false;
    }

    if (signer_time.end_validity < certificate_time.end_validity) {
        return false;
    }

    return true;
}

bool check_permission_consistency(const Certificate& certificate, const Certificate& signer)
{
    auto certificate_aids = get_aids(*certificate);
    auto signer_aids = get_aids(*signer);

    auto compare = [](ItsAid a, ItsAid b) { return a < b; };

    certificate_aids.sort(compare);
    signer_aids.sort(compare);

    return std::includes(signer_aids.begin(), signer_aids.end(), certificate_aids.begin(), certificate_aids.end());

}

bool check_subject_assurance_consistency(const Certificate& certificate, const Certificate& signer)
{
    // TODO
    return true;
}

bool check_region_consistency(const Certificate& certificate, const Certificate& signer)
{
    // TODO
    return true;
}

bool check_consistency(const Certificate& certificate, const Certificate& signer)
{
    if (!check_time_consistency(certificate, signer)) {
        return false;
    }

    if (!check_permission_consistency(certificate, signer)) {
        return false;
    }

    if (!check_subject_assurance_consistency(certificate, signer)) {
        return false;
    }

    if (!check_region_consistency(certificate, signer)) {
        return false;
    }

    return true;
}

CertificateValidity DefaultCertificateValidator::check_certificate(const Certificate& certificate)
{
    HashedId8 signer_hash = certificate.get_issuer_identifier();

    // Only root CA certificates can be self signed, check if we have root CA
    // certificate in trust store
    if (certificate.issuer_is_self()) {
        bool is_trusted = !m_trust_store.lookup(signer_hash).empty();
        return is_trusted ? CertificateValidity::valid() : CertificateInvalidReason::Unknown_Signer;
    }

    if (signer_hash == HashedId8{{0,0,0,0,0,0,0,0}}) {
        return CertificateInvalidReason::Invalid_Signer;
    }

    auto sig = get_signature(*certificate);
    if (!sig) {
        return CertificateInvalidReason::Missing_Signature;
    }

    ByteBuffer cert_buf = asn1::encode_oer(asn_DEF_Vanetza_Security_ToBeSignedCertificate, &certificate->toBeSigned);

    // Authorization tickets are signed by authorization authorities, check if
    // we have authorization authority certificate in cache
    const Certificate* signer_cert = m_cert_cache.lookup(signer_hash);
    if (signer_cert) {
        auto verification_key = get_public_key(**signer_cert);
        if (verification_key) {
            ByteBuffer cert_hash = m_backend.calculate_hash(verification_key->type, cert_buf);
            ByteBuffer signer_hash = m_backend.calculate_hash(verification_key->type, signer_cert->encode());
            ByteBuffer concat_hash = cert_hash;
            concat_hash.insert(concat_hash.end(), signer_hash.begin(), signer_hash.end());
            ByteBuffer signature_input = m_backend.calculate_hash(verification_key->type, concat_hash);

            if (m_backend.verify_digest(*verification_key, signature_input, *sig)) {
                // TODO check certificate consistency
                if (!check_consistency(certificate, *signer_cert)) {
                    return CertificateInvalidReason::Inconsistent_With_Signer;
                }

                return CertificateValidity::valid();
            }
        }
    }

    // There seems to be no way of adding AA certificates to the cache as the
    // signed message is constrained to only contain ONE certificate, which
    // will always be the AT. This would mean that AA certificates shall be
    // inserted into the cache when parsing RCA trust lists by calling this
    // function with the AA certificate as argument. nfiniity's implementation
    // however does not do this, as it believes a SignerIdentifier of type
    // certificate chain with the complete chain is legitimate.

    // Authorization authority certificates must be signed by root CA, check if
    // we have root CA certificate in trust store
    auto trust_store_matches = m_trust_store.lookup(signer_hash);
    if (trust_store_matches.empty()) {
        return CertificateInvalidReason::Unknown_Signer;
    }
    // TODO check if certificate is revoked
    for (auto& possible_signer : trust_store_matches) {
        auto verification_key = get_public_key(*possible_signer);
        if (verification_key) {
            ByteBuffer cert_hash = m_backend.calculate_hash(verification_key->type, cert_buf);
            ByteBuffer signer_hash = m_backend.calculate_hash(verification_key->type, possible_signer.encode());
            ByteBuffer concat_hash = cert_hash;
            concat_hash.insert(concat_hash.end(), signer_hash.begin(), signer_hash.end());
            ByteBuffer signature_input = m_backend.calculate_hash(verification_key->type, concat_hash);

            if (m_backend.verify_digest(*verification_key, signature_input, *sig)) {
                // TODO check certificate consistency
                if (!check_consistency(certificate, *signer_cert)) {
                    return CertificateInvalidReason::Inconsistent_With_Signer;
                }

                return CertificateValidity::valid();
            }
        }
    }

    return CertificateInvalidReason::Unknown_Signer;
}

} // namespace v3
} // namespace security
} // namespace vanetza
