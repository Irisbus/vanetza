#include <vanetza/security/v3/basic_elements.hpp>
#include <vanetza/security/v3/verification.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

bool check_generation_time(const SecuredMessage& message, Clock::time_point now)
{
    using Time64 = std::uint64_t;
    using namespace std::chrono;

    bool valid = false; // TS 103 097 v1.3.1 demands generation time to be always present
    boost::optional<Time64> generation_time = message.generation_time();
    if (generation_time) {
        static const Clock::duration generation_time_future_default = milliseconds(200);
        // Extra time to account for request/response round trip
        static const Clock::duration generation_time_future_certs = seconds(3);

        static const Clock::duration generation_time_past_default = minutes(10);
        static const Clock::duration generation_time_past_ca = seconds(2);
        // This is not specified, so we assume this is equal
        // to the maximum validity of a CA certificate (5 years)
        static const Clock::duration generation_time_past_ctl_crl = hours(43800);

        auto generation_time_future = generation_time_future_default;
        auto generation_time_past = generation_time_past_default;

        const ItsAid its_aid = message.its_aid();
        if (aid::CA == its_aid) {
            generation_time_past = generation_time_past_ca;
        }
        else if (aid::CTL == its_aid || aid::CRL == its_aid) {
            generation_time_future = generation_time_future_certs;
            generation_time_past = generation_time_past_ctl_crl;
        }
        else if (aid::SCR == its_aid) {
            generation_time_future = generation_time_future_certs;
        }

        if (*generation_time > convert_time64(now + generation_time_future)) {
            valid = false;
        }
        else if (*generation_time < convert_time64(now - generation_time_past)) {
            valid = false;
        }
        else {
            valid = true;
        }
    }

    return valid;
}

bool check_certificate_time(const Certificate& certificate, Clock::time_point now)
{
    auto time = certificate.get_start_and_end_validity();
    auto time_now = convert_time32(now);

    if (time.start_validity > time_now || time.end_validity < time_now) {
        return false; // premature or outdated
    }

    return true;
}

bool check_certificate_region(const Certificate& certificate, const PositionFix& position)
{
    auto region = certificate.get_region();

    if (get_type(region) == v2::RegionType::None) {
        return true;
    }

    if (!position.confidence) {
        // return false; // cannot check region restrictions without good position fix
        return true; // do not invalidate based on bad position fix for now
    }

    return v2::is_within(v2::TwoDLocation(position.latitude, position.longitude), region);
}

} // namespace v3
} // namespace security
} // namespace vanetza
