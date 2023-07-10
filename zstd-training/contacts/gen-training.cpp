#include <fmt/format.h>
#include <oxenc/hex.h>
#include <oxenc/bt_serialize.h>
#include <pybind11/embed.h>
#include <pybind11/stl.h>
#include <sodium.h>
#include <sodium/randombytes.h>

#include <chrono>
#include <fstream>
#include <random>
#include <session/config/contacts.hpp>

using ustring = std::basic_string<unsigned char>;
using ustring_view = std::basic_string_view<unsigned char>;
inline ustring operator""_hexbytes(const char* x, size_t n) {
    ustring bytes;
    oxenc::from_hex(x, x + n, std::back_inserter(bytes));
    return bytes;
}

constexpr double prob_approved_me = 0.98;
constexpr double prob_approved = 0.87;
constexpr double prob_name = 0.99;
constexpr double prob_name_is_sessionid = 0.03;  // conditional on having a name
constexpr double prob_pic = 0.43;
constexpr double prob_nickname = 0.02;
constexpr double prob_blocked = 0.015;
constexpr double prob_disappear = 0.04;
constexpr double prob_disappear_aft_read = 0.5;
constexpr double prob_notif_all = 0.01;
constexpr double prob_notif_none = 0.05;  // Conditional on not set to all
constexpr double prob_mute = 0.01;
constexpr double prob_hide = 0.02;
constexpr double prob_prio = 0.04;  // conditional on not hidden

// The number of contacts we generate per simulated training data; we always generate at least 1
// with the actual number drawn from the distribution below.
constexpr double mean_contacts = 20;
// Exponential distribution for some potential long tails.  Subtract 0.5 rather than 1 because we
// truncate this to an integer which reduces its mean by approximately 0.5, so the mean of this,
// pre-truncation, will be the inverse of the parameter (i.e. mean_contacts-0.5), but after integer
// truncation we drop (on average) 0.5, thus landing us at mean_contacts-1 (we get the 1 back
// because we always add 1 to ensure we always have at least one contact).
std::exponential_distribution contacts_size_dist{1. / (mean_contacts - 0.5)};

// Each file is a config push containing (on average) `mean_contacts`
constexpr size_t training_files = 500;

namespace py = pybind11;

py::scoped_interpreter start_python() {
    PyConfig config;
    PyConfig_InitPythonConfig(&config);
    config.parse_argv = 0;
    config.install_signal_handlers = 0;
    return py::scoped_interpreter{&config, 0, nullptr, false};
}

auto python = start_python();
auto pynames = py::module_::import("names");

auto rng = std::mt19937_64{std::random_device{}()};

std::string random_sid() {
    char sid[33];
    sid[0] = 0x05;
    randombytes_buf(&sid[1], 32);
    return oxenc::to_hex(std::begin(sid), std::end(sid));
}

std::string random_name() {
    return pynames.attr("get_full_name")().cast<std::string>();
}

std::uniform_real_distribution unit_rand{0.0, 1.0};
bool random_chance(double prob) {
    return unit_rand(rng) < prob;
}

uint64_t random_fileid() {
    return std::uniform_int_distribution<uint64_t>{0, 1ULL << 53}(rng);
}

ustring random_key(size_t size = 32) {
    ustring k;
    k.resize(size);
    randombytes_buf(k.data(), size);
    return k;
}

template <typename T = int>
T random_of(const std::vector<T>& vals) {
    auto i = std::uniform_int_distribution<size_t>{0, vals.size()}(rng);
    return vals[i];
}

int main() {
    using namespace session::config;

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    assert(rc == 0);

    for (size_t file_i = 0; file_i < training_files; file_i++) {
        Contacts contacts{ustring_view{seed}, std::nullopt};

        for (size_t num_contacts = 1 + (size_t)contacts_size_dist(rng); num_contacts > 0;
             num_contacts--) {

            auto sid = random_sid();
            auto c = contacts.get_or_construct(sid);
            if (random_chance(prob_name))
                // We use a *different* random session id here because we don't want the training to
                // think some particular long string (which will never occur in the real world) got
                // repeated and might be worth adding to the dictionary.
                c.set_name(random_chance(prob_name_is_sessionid) ? random_sid() : random_name());
            if (random_chance(prob_nickname))
                c.set_nickname(random_name());
            if (random_chance(prob_approved))
                c.approved = true;
            if (random_chance(prob_approved_me))
                c.approved_me = true;
            if (random_chance(prob_pic)) {
                c.profile_picture.url =
                        fmt::format("http://filev2.getsession.org/file/{}", random_fileid());
                c.profile_picture.key = random_key();
            }
            if (random_chance(prob_blocked))
                c.blocked = true;
            if (random_chance(prob_disappear)) {
                c.exp_mode = random_chance(prob_disappear_aft_read) ? expiration_mode::after_read
                                                                    : expiration_mode::after_send;
                if (c.exp_mode == expiration_mode::after_read)
                    c.exp_timer = random_of<std::chrono::seconds>(
                            {5min, 1h, 12h, 24h, 7 * 24h, 14 * 24h});
                else
                    c.exp_timer = random_of<std::chrono::seconds>({12h, 24h, 7 * 24h, 14 * 24h});
            }
            if (random_chance(prob_notif_all))
                c.notifications = notify_mode::all;
            else if (random_chance(prob_notif_none))
                c.notifications = notify_mode::disabled;
            if (random_chance(prob_mute))
                c.mute_until = std::chrono::duration_cast<std::chrono::seconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count() +
                               std::uniform_int_distribution<int64_t>{0, 5 * 365 * 86400}(rng);
            if (random_chance(prob_hide))
                c.priority = -1;
            else if (random_chance(prob_prio))
                c.priority = 1 + (int)std::exponential_distribution{1. / 3.}(rng);

            contacts.set(c);
        }

        auto d = contacts.dump();
        std::string_view data{reinterpret_cast<const char*>(d.data()), d.size()};
        auto val = oxenc::bt_deserialize<oxenc::bt_dict>(data);
        auto& push = var::get<std::string>(val.at("$"));

        std::ofstream f{
                fmt::format("../zstd-training/contacts/{:04d}.push", file_i),
                std::ios::binary | std::ios::trunc};
        f.exceptions(std::ios::failbit);
        f.write(push.data(), push.size());
    }
}
