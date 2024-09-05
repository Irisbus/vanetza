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

    bool valid = false;
    boost::optional<Time64> generation_time = message.generation_time();
    if (generation_time) {
        // Values are picked from C2C-CC Basic System Profile v1.1.0, see RS_BSP_168
        static const auto generation_time_future = milliseconds(40);
        static const Clock::duration generation_time_past_default = minutes(10);
        static const Clock::duration generation_time_past_ca = seconds(2);
        auto generation_time_past = generation_time_past_default;

        const ItsAid its_aid = message.its_aid();
        if (aid::CA == its_aid) {
            generation_time_past = generation_time_past_ca;
        }

        if (*generation_time > convert_time64(now + generation_time_future)) {
            valid = false;
        } else if (*generation_time < convert_time64(now - generation_time_past)) {
            valid = false;
        } else {
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

} // namespace v3
} // namespace security
} // namespace vanetza
