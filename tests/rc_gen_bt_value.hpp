#ifndef RC_BT_VALUE_GEN_HPP
#define RC_BT_VALUE_GEN_HPP

#include <oxenc/bt_value.h>
#include <rapidcheck.h>

using oxenc::bt_value;

namespace rc {

Gen<bt_value> gen_bt_value();

template <>
struct Arbitrary<bt_value> {
    static Gen<bt_value> arbitrary() { return rc::gen_bt_value(); }
};

}  // namespace rc

#endif  // RC_BT_VALUE_GEN_HPP
