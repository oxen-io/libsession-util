#include <oxenc/bt_value.h>
#include <rapidcheck.h>

using oxenc::bt_dict;
using oxenc::bt_list;
using oxenc::bt_value;

namespace rc {

Gen<bt_value> gen_bt_value() {
    return gen::oneOf<bt_value>(
            gen::map(
                    gen::arbitrary<std::string>(),
                    [](const std::string& s) { return bt_value{s}; }),
            gen::map(
                    // FIXME: Don't know how to generate random string_view on the fly without
                    // messing up life cycle
                    gen::just(std::string_view("<string_view placeholder>")),
                    [](const std::string_view& s) { return bt_value{s}; }),
            gen::map(gen::arbitrary<int64_t>(), [](int64_t i) { return bt_value{i}; }),
            gen::map(gen::arbitrary<uint64_t>(), [](uint64_t i) { return bt_value{i}; }),
            gen::map(
                    gen::scale(0.5, gen::container<bt_list>(gen::lazy(&gen_bt_value))),
                    [](const bt_list& list) { return bt_value{list}; }),
            gen::map(
                    gen::scale(
                            0.5,
                            gen::container<bt_dict>(
                                    gen::arbitrary<std::string>(), gen::lazy(&gen_bt_value))),
                    [](const bt_dict& dict) { return bt_value{dict}; }));
}

template <>
struct Arbitrary<bt_value> {
    static Gen<bt_value> arbitrary() { return rc::gen_bt_value(); }
};

}  // namespace rc
