#pragma once
#include <vanetza/common/clock.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/secured_message.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

bool check_generation_time(const SecuredMessage& message, Clock::time_point now);
bool check_certificate_time(const Certificate& certificate, Clock::time_point now);

} // namespace v3
} // namespace security
} // namespace vanetza
