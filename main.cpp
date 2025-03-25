#include <iostream>
#include <array>
#include <vector>
#include <cstdint>
#include <cstring>
#include <functional>
#include <variant>
#include <string>
#include <fstream>
#include <type_traits>
#include <stdexcept>
#include <iterator>
#include <iomanip>

using Id = uint64_t;
using Buffer = std::vector<std::byte>;
enum class TypeId : Id { Uint = 0, Float = 1, String = 2, Vector = 3 };

class IntegerType;
class FloatType;
class StringType;
class VectorType;
class Any;

class Tracer {
public:
    static constexpr bool ENABLED = false; // Set to true to enable logging

    static inline int depth = 0;

    class Scope {
    public:
        Scope() noexcept { if constexpr (ENABLED) Tracer::depth++; }
        ~Scope() noexcept { if constexpr (ENABLED) Tracer::depth--; }
    };

    template<typename... Args>
    static inline void logHex(Args&&... args) noexcept {
        if constexpr (ENABLED) {
            const auto* data = std::get<0>(std::forward_as_tuple(args...));
            const size_t size = std::get<1>(std::forward_as_tuple(args...));
            const std::string& prefix = sizeof...(Args) > 2 ? std::get<2>(std::forward_as_tuple(args...)) : "";
            std::cout << std::string(depth * 2, ' ') << prefix;
            for (size_t i = 0; i < size; ++i) {
                printf("%02x ", static_cast<int>(data[i]));
            }
            std::cout << "\n";
        }
    }

    template<typename... Args>
    static inline void log(Args&&... args) noexcept {
        if constexpr (ENABLED) {
            const char type = std::get<0>(std::forward_as_tuple(args...));
            const std::string& msg = std::get<1>(std::forward_as_tuple(args...));
            std::cout << std::string(depth * 2, ' ') << "[" << type << "] " << msg << "\n";
        }
    }
};
    
namespace Detail {
    template<TypeId> struct TypeIdToType;
    template<> struct TypeIdToType<TypeId::Uint> { using type = IntegerType; };
    template<> struct TypeIdToType<TypeId::Float> { using type = FloatType; };
    template<> struct TypeIdToType<TypeId::String> { using type = StringType; };
    template<> struct TypeIdToType<TypeId::Vector> { using type = VectorType; };

    template <typename T>
    void writeLE(Buffer& buf, T value, const std::string& desc = "") {
        const auto* ptr = reinterpret_cast<const std::byte*>(&value);
        Tracer::logHex(ptr, sizeof(T), "WRITE " + desc + ": ");
        buf.insert(buf.end(), ptr, ptr + sizeof(T));
    }

    template <typename T>
    T readLE(Buffer::const_iterator& it, Buffer::const_iterator end,
        const std::string& desc = ""
    ) {
        if (std::distance(it, end) < static_cast<ptrdiff_t>(sizeof(T))) {
            throw std::runtime_error("Buffer underflow while reading " + desc +
                ". Required: " + std::to_string(sizeof(T)) +
                ", available: " + std::to_string(std::distance(it, end)));
        }
        
        T value;
        std::memcpy(&value, &*it, sizeof(T));
        Tracer::logHex(&*it, sizeof(T), "READ " + desc + ": ");
        it += sizeof(T);
        return value;
    }

    template<typename T>
    struct is_valid_type : std::disjunction<
        std::is_same<T, IntegerType>,
        std::is_same<T, FloatType>,
        std::is_same<T, StringType>,
        std::is_same<T, VectorType>
    > {};
}

template<typename Derived, typename ValueType>
class DataHolder {
protected:
    ValueType value;

    explicit constexpr DataHolder(ValueType v) noexcept : value(v) {}
    DataHolder() = default;
    DataHolder(const DataHolder&) = default;
    DataHolder(DataHolder&&) noexcept = default;
    DataHolder& operator=(const DataHolder&) = default;
    DataHolder& operator=(DataHolder&&) noexcept = default;
    ~DataHolder() = default;

    friend Derived;

public:
    [[nodiscard]] static constexpr TypeId getTypeId() noexcept {
        return Derived::ID;
    }

    void serialize(Buffer& buf) const {
        Detail::writeLE(buf, static_cast<Id>(Derived::ID), "TypeID");
        static_cast<const Derived*>(this)->serializeImpl(buf);
    }

    [[nodiscard]] static Derived deserialize(Buffer::const_iterator& it, Buffer::const_iterator end) {
        return Derived::deserializeImpl(it, end);
    }
    [[nodiscard]] size_t getSerializedSize() const noexcept {
        return sizeof(Id) + static_cast<const Derived*>(this)->getSerializedSizeImpl();
    }
    [[nodiscard]] bool operator==(const DataHolder& o) const noexcept { return value == o.value; }
    [[nodiscard]] const ValueType& getValue() const noexcept { return value; }
    [[nodiscard]] ValueType& getValue() noexcept { return value; }
};

class IntegerType final : public DataHolder<IntegerType, uint64_t> {
public:
    static constexpr TypeId ID = TypeId::Uint;
    
    explicit constexpr IntegerType(uint64_t v = 0) noexcept : DataHolder(v) {}
    
    void serializeImpl(Buffer& buf) const {
        Tracer::log('I', "value: " + std::to_string(value));
        Detail::writeLE(buf, value, "I-Value");
    }

    [[nodiscard]] static IntegerType deserializeImpl(Buffer::const_iterator& it, Buffer::const_iterator end) {
        auto val = Detail::readLE<uint64_t>(it, end, "I-Value");
        Tracer::log('I', "value: " + std::to_string(val));
        return IntegerType(val);
    }

    [[nodiscard]] size_t getSerializedSizeImpl() const noexcept {
        return sizeof(value);
    }
};

class FloatType final : public DataHolder<FloatType, double> {
public:
    static constexpr TypeId ID = TypeId::Float;
    
    explicit constexpr FloatType(double v = 0.0) noexcept : DataHolder(v) {}
    
    void serializeImpl(Buffer& buf) const {
        Tracer::log('F', "value: " + std::to_string(value));
        Detail::writeLE(buf, value, "F-Value");
    }

    [[nodiscard]] static FloatType deserializeImpl(Buffer::const_iterator& it, Buffer::const_iterator end) {
        auto val = Detail::readLE<double>(it, end, "F-Value");
        Tracer::log('F', "value: " + std::to_string(val));
        return FloatType(val);
    }

    [[nodiscard]] size_t getSerializedSizeImpl() const noexcept {
        return sizeof(value);
    }
};

class StringType final : public DataHolder<StringType, std::string> {
public:
    static constexpr TypeId ID = TypeId::String;
    
    template <typename... Args,
              typename = std::enable_if_t<std::is_constructible_v<std::string, Args...>>>
    explicit StringType(Args&&... args) noexcept(std::is_nothrow_constructible_v<std::string, Args...>)
        : DataHolder(std::string(std::forward<Args>(args)...)) {}

    void serializeImpl(Buffer& buf) const {
        Tracer::log('S', "Value: \"" + value + "\"");
        const Id size = value.size();
        Detail::writeLE(buf, size, "S-Size");
        
        const auto* data = reinterpret_cast<const std::byte*>(value.data());
        Tracer::logHex(data, value.size(), "S-Data");
        buf.insert(buf.end(), data, data + size);
    }

    [[nodiscard]] static StringType deserializeImpl(Buffer::const_iterator& it, Buffer::const_iterator end) {
        const auto size = Detail::readLE<Id>(it, end, "S-Size");
        
        if (std::distance(it, end) < static_cast<ptrdiff_t>(size)) {
            throw std::runtime_error("String data truncated");
        }

        std::string str(size, '\0');
        std::memcpy(str.data(), &*it, size);
        Tracer::logHex(&*it, size, "S-Data");
        it += size;
        
        Tracer::log('S', "value: \"" + str + "\"");
        return StringType(std::move(str));
    }

    [[nodiscard]] size_t getSerializedSizeImpl() const noexcept {
        return sizeof(Id) + value.size();
    }
};

class VectorType final : public DataHolder<VectorType, std::vector<Any>> {
public:
    static constexpr TypeId ID = TypeId::Vector;

    template<typename... Args,
        typename = std::enable_if_t<(Detail::is_valid_type<std::decay_t<Args>>::value && ...)>>
    explicit VectorType(Args&&... args) noexcept(std::is_nothrow_constructible_v<std::string, Args...>)
        : DataHolder(std::vector<Any>{}) {
        value.reserve(sizeof...(Args));
        (value.emplace_back(std::forward<Args>(args)), ...);
    }

    template<typename Arg, typename = std::enable_if_t<
        Detail::is_valid_type<std::decay_t<Arg>>::value>>
    void push_back(Arg&& val) {
        value.emplace_back(std::forward<Arg>(val));
    }

    void serializeImpl(Buffer& buf) const;
    [[nodiscard]] static VectorType deserializeImpl(Buffer::const_iterator& it, Buffer::const_iterator end);
    [[nodiscard]] size_t getSerializedSizeImpl() const noexcept;
};

class Any final {
private:
    std::variant<IntegerType, FloatType, StringType, VectorType> data;

public:
    Any() noexcept : data(IntegerType{0}) {}
    Any(const Any&) = default;
    Any(Any&&) noexcept = default;
    Any& operator=(const Any&) = default;
    Any& operator=(Any&&) noexcept = default;

    template<typename T, typename = std::enable_if_t<Detail::is_valid_type<std::decay_t<T>>::value>>
    explicit Any(T&& val) noexcept(std::is_nothrow_constructible_v<decltype(data), T&&>)
        : data(std::forward<T>(val)) {
    }

    void serialize(Buffer& buf) const {
        std::visit([&](const auto& v) { v.serialize(buf); }, data);
    }

    [[nodiscard]] Buffer::const_iterator deserialize(Buffer::const_iterator it, Buffer::const_iterator end) {
        const auto typeId = static_cast<TypeId>(Detail::readLE<Id>(it, end, "TypeId"));
        switch(typeId) {
            case TypeId::Uint:  data = IntegerType::deserialize(it, end); break;
            case TypeId::Float: data = FloatType::deserialize(it, end); break;
            case TypeId::String: data = StringType::deserialize(it, end); break;
            case TypeId::Vector: data = VectorType::deserialize(it, end); break;
            default: throw std::runtime_error("Invalid type ID");
        }
        return it;
    }

    [[nodiscard]] size_t getSerializedSize() const noexcept {
        return std::visit([](const auto& v) { return v.getSerializedSize(); }, data);
    }

    [[nodiscard]] TypeId getPayloadTypeId() const noexcept { 
        return static_cast<TypeId>(data.index());
    }

    template<typename T, typename = std::enable_if_t<Detail::is_valid_type<T>::value>>
    [[nodiscard]] const auto& get() const {
        if (!std::holds_alternative<T>(data)) {
            throw std::bad_variant_access{};
        }
        return std::get<std::decay_t<T>>(data);
    }

    template<TypeId kId>
    [[nodiscard]] const auto& get() const {
        using T = typename Detail::TypeIdToType<kId>::type;
        return std::get<T>(data);
    }
    
    [[nodiscard]] bool operator==(const Any& o) const noexcept { return data == o.data; }

};

void VectorType::serializeImpl(Buffer& buf) const {
    Tracer::log('V', "Vector size: " + std::to_string(value.size()));
    Detail::writeLE(buf, static_cast<Id>(value.size()), "VectorSize");
    
    {
        Tracer::Scope s;
        for (const auto& item : value) {
            item.serialize(buf);
        }
    }
}

VectorType VectorType::deserializeImpl(Buffer::const_iterator& it, Buffer::const_iterator end) {
    const auto size = Detail::readLE<Id>(it, end, "VectorSize");
    Tracer::log('V', "Deserializing vector size: " + std::to_string(size));
    
    VectorType vec;
    vec.value.reserve(size);
    
    {
        Tracer::Scope s;
        for (Id i = 0; i < size; ++i) {
            Any item;
            it = item.deserialize(it, end);
            vec.value.emplace_back(std::move(item));
        }
    }
    return vec;
}

size_t VectorType::getSerializedSizeImpl() const noexcept {
    size_t size = sizeof(Id);
    for (const auto& item : value) {
        size += item.getSerializedSize();
    }
    return size;
}

class Serializator final {
private:
    std::vector<Any> storage;

    size_t calculateSerializedSize() const noexcept {
        size_t size = sizeof(Id);
        for (const auto& item : storage) {
            size += sizeof(Id);
            size += item.getSerializedSize();
        }
        return size;
    }

public:
    template<typename Arg>
    void push(Arg&& val) {
        if constexpr (std::is_same_v<std::decay_t<Arg>, VectorType>) {
            storage.emplace_back(VectorType(std::move(val)));
        } else {
            storage.emplace_back(std::forward<Arg>(val));
        }
    }

    [[nodiscard]] Buffer serialize() const {
        Buffer buf;
        buf.reserve(calculateSerializedSize());

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
            Id size = Detail::readLE<Id>(it, buff.end(), "Storage-Size");
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
        std::cout << "Result: " << (manual_data == new_buf) << "\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
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
        s.push(StringType("qwerty"));
        s.push(IntegerType(100500));
        s.push(vec);
        Buffer test_buf = s.serialize();
        
        auto test_res = Serializator::deserialize(test_buf);
        bool test_ok = test_res.size() == 3 && 
                      test_res[0].getPayloadTypeId() == TypeId::String;
        
        if (test_ok) {
            const auto& res_vec = test_res[2].get<VectorType>().getValue();
            test_ok = res_vec.size() == 2 &&
                res_vec[0].getPayloadTypeId() == TypeId::String &&
                res_vec[0].get<StringType>().getValue() == "qwerty" &&
                res_vec[1].getPayloadTypeId() == TypeId::Uint &&
                res_vec[1].get<IntegerType>().getValue() == 100500;
        }
        
        std::cout << "\nManual test result: " << test_ok << std::endl;
    }
    catch (const std::exception& e) {
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