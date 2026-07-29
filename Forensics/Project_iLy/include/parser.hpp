#ifndef PARSER_HPP
#define PARSER_HPP

#include "pif.hpp"
#include <string>
#include <vector>
#include <map>
#include <iostream>

namespace Json {

enum class Type { Null, Bool, Number, String, Array, Object };

struct Value {
    Type type = Type::Null;
    bool bool_val = false;
    double num_val = 0.0;
    std::string str_val;
    std::vector<Value> arr_val;
    std::map<std::string, Value> obj_val;

    bool is_null() const { return type == Type::Null; }
    bool is_bool() const { return type == Type::Bool; }
    bool is_number() const { return type == Type::Number; }
    bool is_string() const { return type == Type::String; }
    bool is_array() const { return type == Type::Array; }
    bool is_object() const { return type == Type::Object; }

    bool get_bool(bool def = false) const { return type == Type::Bool ? bool_val : def; }
    double get_double(double def = 0.0) const { return type == Type::Number ? num_val : def; }
    std::string get_string(const std::string& def = "") const { return type == Type::String ? str_val : def; }

    const Value& operator[](const std::string& key) const {
        static const Value null_val;
        if (type != Type::Object) return null_val;
        auto it = obj_val.find(key);
        if (it == obj_val.end()) return null_val;
        return it->second;
    }

    const Value& operator[](size_t idx) const {
        static const Value null_val;
        if (type != Type::Array) return null_val;
        if (idx >= arr_val.size()) return null_val;
        return arr_val[idx];
    }

    size_t size() const {
        if (type == Type::Array) return arr_val.size();
        if (type == Type::Object) return obj_val.size();
        return 0;
    }
};

Value parse(const std::string& src);

} // namespace Json

namespace Parser {

// Base interface for CSV and JSON logs
class LogParser {
public:
    virtual ~LogParser() = default;
    virtual std::vector<PiF::PiFEvent> parseFile(const std::string& filepath) = 0;
};

class CSVParser : public LogParser {
public:
    std::vector<PiF::PiFEvent> parseFile(const std::string& filepath) override;
private:
    std::vector<std::string> splitRow(const std::string& row, char delimiter);
};

class JSONParser : public LogParser {
public:
    std::vector<PiF::PiFEvent> parseFile(const std::string& filepath) override;
};

// Orchestrator to parse and return normalized PiF events
std::vector<PiF::PiFEvent> parseLog(const std::string& filepath);

} // namespace Parser

#endif // PARSER_HPP
