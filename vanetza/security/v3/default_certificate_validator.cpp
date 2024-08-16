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

    ByteBuffer cert_buf = certificate.encode();

    // Authorization tickets are signed by authorization authorities, check if
    // we have authorization authority certificate in cache
    const Certificate* signer_cert = m_cert_cache.lookup(signer_hash);
    if (signer_cert) {
        auto verification_key = get_public_key(**signer_cert);
        if (verification_key) {
            ByteBuffer signer_hash = m_backend.calculate_hash(verification_key->type, signer_cert->encode());
            ByteBuffer cert_hash = m_backend.calculate_hash(verification_key->type, cert_buf);
            ByteBuffer concat_hash = signer_hash;
            concat_hash.insert(concat_hash.end(), cert_hash.begin(), cert_hash.end());
            ByteBuffer signature_input = m_backend.calculate_hash(verification_key->type, concat_hash);

            if (m_backend.verify_digest(*verification_key, signature_input, *sig)) {
                // TODO check certificate consistency
                return CertificateValidity::valid();
            }
        }
    }

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
            ByteBuffer signer_hash = m_backend.calculate_hash(verification_key->type, signer_cert->encode());
            ByteBuffer cert_hash = m_backend.calculate_hash(verification_key->type, cert_buf);
            ByteBuffer concat_hash = signer_hash;
            concat_hash.insert(concat_hash.end(), cert_hash.begin(), cert_hash.end());
            ByteBuffer signature_input = m_backend.calculate_hash(verification_key->type, concat_hash);

            if (m_backend.verify_digest(*verification_key, signature_input, *sig)) {
                // TODO check certificate consistency
                return CertificateValidity::valid();
            }
        }
    }

    return CertificateInvalidReason::Unknown_Signer;
}

} // namespace v3
} // namespace security
} // namespace vanetza
