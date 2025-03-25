#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <variant>
#include <string>
#include <fstream>
#include <type_traits>
#include <stdexcept>
#include <iomanip>

// #define ENABLE_LOGGING

class Any;
class VectorType;

struct Tracer {
    static inline int depth = 0;
    
    class Scope {
    public:
        Scope() noexcept { Tracer::depth++; }
        ~Scope() noexcept { Tracer::depth--; }
    };

    static inline void logHex(
        const std::byte* data,
        size_t size,
        const std::string& prefix = ""
    ) noexcept {
        #ifdef ENABLE_LOGGING
        std::cout << std::string(depth*2, ' ') << prefix;
        for (size_t i = 0; i < size; ++i) {
            printf("%02x ", static_cast<int>(data[i]));
        }
        std::cout << "\n";
        #endif
    }
    
    static inline void log(char type, const std::string& msg) noexcept {
        #ifdef ENABLE_LOGGING
        std::cout << std::string(depth*2, ' ') 
                << "[" << type << "] " << msg << "\n";
        #endif
    }
};

template <typename T>
struct DataHolder {
    T value;
    
    explicit DataHolder(T v = T{}) noexcept : value(std::move(v)) {}
    [[nodiscard]] const T& get() const noexcept { return value; }
    bool operator==(const DataHolder& o) const noexcept { return value == o.value; }
};

using IntegerType = DataHolder<uint64_t>;
using FloatType = DataHolder<double>;
using StringType = DataHolder<std::string>;

using Id = uint64_t;
using Buffer = std::vector<std::byte>;
enum class TypeId : Id { Uint = 0, Float = 1, String = 2, Vector = 3 };

namespace Detail {
    template <typename T>
    void writeLE(Buffer& buf, T value, const std::string& desc = "") noexcept {
        // std::array<std::byte, sizeof(T)> bytes;
        // std::memcpy(bytes.data(), &value, sizeof(T));
        const auto* ptr = reinterpret_cast<const std::byte*>(&value);
        Tracer::logHex(ptr, sizeof(T), "WRITE " + desc + ": ");
        buf.insert(buf.end(), ptr, ptr + sizeof(T));
    }

    template <typename T>
    [[nodiscard]] T readLE(Buffer::const_iterator& it, const std::string& desc = "") {
        T value;
        std::memcpy(&value, &*it, sizeof(T));
        Tracer::logHex(&*it, sizeof(T), "READ " + desc + ": ");
        it += sizeof(T);
        return value;
    }

    inline void log_raw_data(const Buffer& buf, size_t offset, size_t size, const std::string& desc) noexcept {
        #ifdef ENABLE_LOGGING
        Tracer::logHex(buf.data() + offset, size, "RAW " + desc + ": ");
        #endif
    }

    template<typename T>
    struct is_valid_type : std::disjunction<
        std::is_same<std::decay_t<T>, IntegerType>,
        std::is_same<std::decay_t<T>, FloatType>,
        std::is_same<std::decay_t<T>, StringType>,
        std::is_same<std::decay_t<T>, VectorType>
    > {};
}

class VectorType final {
    std::vector<Any> items;

public:
    VectorType() noexcept = default;
    VectorType(const VectorType&) = default;
    VectorType(VectorType&&) noexcept = default;
    VectorType& operator=(const VectorType&) = default;
    VectorType& operator=(VectorType&&) noexcept = default;

    template<typename... Args>
    explicit VectorType(Args&&... args) {
        items.reserve(sizeof...(Args));
        (items.emplace_back(std::forward<Args>(args)), ...);
    }

    void push_back(Any&& item);
    
    template<typename Arg>
    auto push_back(Arg&& val) noexcept -> std::enable_if_t<
        Detail::is_valid_type<std::decay_t<Arg>>::value
    > {
        items.emplace_back(std::forward<Arg>(val));
    }

    [[nodiscard]] const std::vector<Any>& get() const noexcept { return items; }
    bool operator==(const VectorType& o) const noexcept;
};

using VariantType = std::variant<IntegerType, FloatType, StringType, VectorType>;

class Any final {
    VariantType data;

public:
    Any() noexcept : data(IntegerType{0}) {}
    Any(const Any&) = default;
    Any(Any&&) noexcept = default;
    Any& operator=(const Any&) = default;
    Any& operator=(Any&&) noexcept = default;

    template<typename T, typename = std::enable_if_t<
        Detail::is_valid_type<std::decay_t<T>>::value
    >>
    explicit Any(T val) noexcept : data(std::move(val)) {}

    [[nodiscard]] TypeId getPayloadTypeId() const noexcept {
        return static_cast<TypeId>(data.index());
    }

    template<typename Type>
    [[nodiscard]] const auto& getValue() const {
        return std::get<Type>(data);
    }

    template<TypeId kId>
    [[nodiscard]] const auto& getValue() const {
        return std::get<static_cast<std::size_t>(kId)>(data);
    }

    void serialize(Buffer& buf) const;
    Buffer::const_iterator deserialize(Buffer::const_iterator it, Buffer::const_iterator end);

    [[nodiscard]] bool operator==(const Any& o) const noexcept { return data == o.data; }
};

void VectorType::push_back(Any&& item) {
    items.push_back(std::move(item));
}

bool VectorType::operator==(const VectorType& o) const noexcept {
    return items == o.items;
}

void Any::serialize(Buffer& buf) const {
    std::visit([&](const auto& v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, IntegerType>) {
            Tracer::log('I', "value: " + std::to_string(v.get()));
            Detail::writeLE(buf, static_cast<Id>(TypeId::Uint), "I-TypeId");
            Detail::writeLE(buf, v.get(), "I-Value");
        }
        else if constexpr (std::is_same_v<T, FloatType>) {
            Tracer::log('F', "value: " + std::to_string(v.get()));
            Detail::writeLE(buf, static_cast<Id>(TypeId::Float), "F-TypeId");
            Detail::writeLE(buf, v.get(), "F-Value");
        }
        else if constexpr (std::is_same_v<T, StringType>) {
            Tracer::log('S', "value: \"" + v.get() + "\"");
            Detail::writeLE(buf, static_cast<Id>(TypeId::String), "S-TypeId");
            Detail::writeLE(buf, static_cast<Id>(v.get().size()), "S-Size");
            const auto* bytes = reinterpret_cast<const std::byte*>(v.get().data());
            Detail::log_raw_data(buf, buf.size(), v.get().size(), "S-Data");
            buf.insert(buf.end(), bytes, bytes + v.get().size());
        }
        else if constexpr (std::is_same_v<T, VectorType>) {
            const auto& vec = v.get();
            Tracer::log('V', "(" + std::to_string(vec.size()) + ")");
            {
                Tracer::Scope s;
                Detail::writeLE(buf, static_cast<Id>(TypeId::Vector), "V-TypeId");
                Detail::writeLE(buf, static_cast<Id>(vec.size()), "V-Size");
                for (const auto& item : vec) {
                    item.serialize(buf);
                }
            }
            Tracer::log('V', "end");
        }
    }, data);
}

Buffer::const_iterator Any::deserialize(Buffer::const_iterator it, Buffer::const_iterator end) {
    TypeId typeId = static_cast<TypeId>(Detail::readLE<Id>(it, "TypeId"));
    
    switch(typeId) {
        case TypeId::Uint: {
            auto val = Detail::readLE<uint64_t>(it, "I-Value");
            data = IntegerType(val);
            Tracer::log('I', "value: " + std::to_string(val));
            break;
        }
        case TypeId::Float: {
            auto val = Detail::readLE<double>(it, "F-Value");
            data = FloatType(val);
            Tracer::log('F', "value: " + std::to_string(val));
            break;
        }
        case TypeId::String: {
            Id size = Detail::readLE<Id>(it, "S-Size");
            std::string str;
            str.resize(size);
            Detail::log_raw_data({it, it + size}, 0, size, "S-Data");
            std::memcpy(str.data(), &*it, size);
            it += size;
            data = StringType(str);
            Tracer::log('S', "value: \"" + str + "\"");
            break;
        }
        case TypeId::Vector: {
            Id size = Detail::readLE<Id>(it, "V-Size");
            Tracer::log('V', "(" + std::to_string(size) + ")");
            {
                Tracer::Scope s;
                VectorType vec;
                for (Id i = 0; i < size; ++i) {
                    Any item;
                    it = item.deserialize(it, end);
                    vec.push_back(std::move(item));
                }
                data = std::move(vec);
            }
            Tracer::log('V', "end");
            break;
        }
        default: throw std::runtime_error("Unknown TypeId");
    }
    return it;
}

class Serializator final {
    std::vector<Any> storage;

public:
    template<typename Arg>
    void push(Arg&& val) {
        storage.emplace_back(std::forward<Arg>(val));
    }

    [[nodiscard]] Buffer serialize() const {
        Buffer buf;
        Tracer::log(' ', "Serialization START");
        {
            Tracer::Scope s;
            Detail::writeLE(buf, static_cast<Id>(storage.size()), "Storage-Size");
            for (const auto& item : storage) {
                item.serialize(buf);
            }
        }
        Tracer::log(' ', "Serialization END");
        return buf;
    }

    [[nodiscard]] static std::vector<Any> deserialize(const Buffer& buff) {
        std::vector<Any> result;
        Tracer::log(' ', "Deserialization START");
        {
            Tracer::Scope s;
            auto it = buff.begin();
            Id size = Detail::readLE<Id>(it, "Storage-Size");
            result.reserve(size);
            for (Id i = 0; i < size; ++i) {
                Any any;
                it = any.deserialize(it, buff.end());
                result.emplace_back(std::move(any));
            }
        }
        Tracer::log(' ', "Deserialization END");
        return result;
    }

    [[nodiscard]] const std::vector<Any>& getStorage() const noexcept {
        return storage;
    }
};

int main() {
    // ==================== TEST 1 ==============================
    try {
        Tracer::log('T', "Starting manual test 1");

        Buffer manual_data = {
            std::byte{0x03}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            
            // check empty string
            std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},

            // check empty vector
            std::byte{0x03}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    
            std::byte{0x03}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            
            std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            
            std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x06}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{'q'}, std::byte{'w'}, std::byte{'e'}, std::byte{'r'},
            std::byte{'t'}, std::byte{'y'}, 
            
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x94}, std::byte{0x88}, std::byte{0x01}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}
        };
    
        auto res = Serializator::deserialize(manual_data);

        Serializator serializer;
        for (auto&& i : res) {
            serializer.push(i);
        }
        
        Buffer new_buf = serializer.serialize();
        std::cout << "Result: " << (manual_data == new_buf) << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    // ==================== TEST 2 ==============================
    try {
        Tracer::log('T', "Starting manual test 2");
        VectorType vec{
            StringType("qwerty"),
            IntegerType(100500)
        };

        Serializator s;
        s.push(vec);
        Buffer test_buf = s.serialize();
        
        auto test_res = Serializator::deserialize(test_buf);
        bool test_ok = test_res.size() == 1 && 
                      test_res[0].getPayloadTypeId() == TypeId::Vector;
        
        if (test_ok) {
            const auto& res_vec = test_res[0].getValue<VectorType>().get();
            test_ok = res_vec.size() == 2 &&
                     res_vec[0].getPayloadTypeId() == TypeId::String &&
                     res_vec[0].getValue<StringType>().get() == "qwerty" &&
                     res_vec[1].getPayloadTypeId() == TypeId::Uint &&
                     res_vec[1].getValue<IntegerType>().get() == 100500;
        }
        
        std::cout << "\nManual test result: " << test_ok << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Manual test failed: " << e.what() << std::endl;
        return 1;
    }

    // return 0;


    // ==================== TEST ORIGINAL ==============================
    std::cout << "File processing ... \n";

    std::ifstream raw;
    raw.open("raw.bin", std::ios_base::in | std::ios_base::binary);
    if (!raw.is_open())
        return 1;
    raw.seekg(0, std::ios_base::end);
    std::streamsize size = raw.tellg();
    raw.seekg(0, std::ios_base::beg);

    Buffer buff(size);
    raw.read(reinterpret_cast<char*>(buff.data()), size);

    auto res = Serializator::deserialize(buff);

    Serializator s;
    for (auto&& i : res)
        s.push(i);

    const Buffer new_buf = s.serialize();
    std::cout << (buff == s.serialize()) << '\n';

    // ==================== TEST OUT FILE ==============================
    std::ofstream out("out.bin", std::ios::binary);
    if (!out.is_open()) {
        std::cerr << "Error creating out.bin" << std::endl;
        return 1;
    }
    
    if (!out.write(reinterpret_cast<const char*>(new_buf.data()), new_buf.size())) {
        std::cerr << "Error writing file" << std::endl;
        return 1;
    }
    out.close();

    std::ifstream f1("raw.bin", std::ios::binary);
    std::ifstream f2("out.bin", std::ios::binary);

    if (!f1 || !f2) {
        std::cerr << "Error opening files\n";
        return 1;
    }

    f1.seekg(0, std::ios::end);
    f2.seekg(0, std::ios::end);
    std::streampos size1 = f1.tellg();
    std::streampos size2 = f2.tellg();
    f1.seekg(0);
    f2.seekg(0);

    std::cout << "File sizes - raw: " << size1 << ", out: " << size2 << "\n";

    if (size1 != size2) {
        std::cout << "Files have different sizes. Comparison aborted.\n";
        return 1;
    }

    bool match = true;
    char c1, c2;
    int pos = 0;
    while (f1.get(c1) && f2.get(c2)) {
        if (c1 != c2) {
            std::cout << "Mismatch at " << pos 
                    << ": raw=0x" << std::hex << (int)(unsigned char)c1
                    << ", out=0x" << (int)(unsigned char)c2 << "\n";
            match = false;
        }
        pos++;
    }

    std::cout << "Files match: " << std::boolalpha << match << "\n";

    return 0;
}