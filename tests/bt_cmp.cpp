#include <oxenc/bt_value.h>

#include <stdexcept>

using oxenc::bt_dict;
using oxenc::bt_list;
using oxenc::bt_value;

bool bt_cmp(const bt_value& a, const bt_value& b) {
    if (a.index() != b.index()) {
        return a.index() < b.index();
    }
    switch (a.index()) {
        case 0: {  // std::string
            auto x = std::get<std::string>(a);
            auto y = std::get<std::string>(b);
            return x < y;
        }
        case 1: {  // std::string_view
            auto x = std::get<std::string_view>(a);
            auto y = std::get<std::string_view>(b);
            return x < y;
        }
        case 2: {  // int64_t
            auto x = std::get<int64_t>(a);
            auto y = std::get<int64_t>(b);
            return x < y;
        }
        case 3: {  // uint64_t
            auto x = std::get<uint64_t>(a);
            auto y = std::get<uint64_t>(b);
            return x < y;
        }
        case 4: {  // bt_list
            auto x = std::get<bt_list>(a);
            auto y = std::get<bt_list>(b);
            if (x.size() != y.size()) {
                return x.size() < y.size();
            }
            return std::lexicographical_compare(x.begin(), x.end(), y.begin(), y.end(), bt_cmp);
        }

        case 5: {  // bt_dict
            const auto& x = std::get<bt_dict>(a);
            const auto& y = std::get<bt_dict>(b);

            auto cmp_dict = [](const auto& a, const auto& b) {
                return a.first < b.first || (a.first == b.first && bt_cmp(a.second, b.second));
            };

            return std::lexicographical_compare(x.begin(), x.end(), y.begin(), y.end(), cmp_dict);
        }
        default: throw std::runtime_error("Invalid bt_value type");
    }
}
