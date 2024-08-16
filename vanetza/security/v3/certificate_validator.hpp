#pragma once
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/certificate_validity.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

class CertificateValidator
{
public:
    /**
     * Check validity of given certificate and consistency with parent certificates.
     * \param certificate given certificate
     * \return validity result
     */
    virtual CertificateValidity check_certificate(const Certificate& certificate) = 0;

    virtual ~CertificateValidator() = default;
};

} // namespace v3
} // namespace security
} // namespace vanetza
