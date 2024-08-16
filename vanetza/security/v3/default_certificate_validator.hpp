#pragma once
#include <vanetza/common/clock.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/trust_store.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

/**
 * \brief The default certificate validator
 */
class DefaultCertificateValidator : public CertificateValidator
{
public:
    DefaultCertificateValidator(Backend&, CertificateCache&, const TrustStore&);

    /**
     * \brief check certificate
     * \param certificate to verify
     * \return certificate status
     */
    CertificateValidity check_certificate(const Certificate& certificate) override;

private:
    Backend& m_backend;
    CertificateCache& m_cert_cache;
    const TrustStore& m_trust_store;
};

} // namespace v3
} // namespace security
} // namespace vanetza
