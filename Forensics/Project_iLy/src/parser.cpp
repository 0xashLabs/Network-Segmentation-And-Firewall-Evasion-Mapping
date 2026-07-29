#include "parser.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace Json {

class ParserInternal {
public:
    explicit ParserInternal(const std::string& s) : src(s), pos(0) {}

    Value parse() {
        skip_whitespace();
        return parse_value();
    }

private:
    const std::string& src;
    size_t pos;

    void skip_whitespace() {
        while (pos < src.size() && (src[pos] == ' ' || src[pos] == '\t' || src[pos] == '\r' || src[pos] == '\n')) {
            pos++;
        }
    }

    char peek() {
        skip_whitespace();
        return pos < src.size() ? src[pos] : '\0';
    }

    char get() {
        skip_whitespace();
        return pos < src.size() ? src[pos++] : '\0';
    }

    Value parse_value() {
        char c = peek();
        if (c == '{') return parse_object();
        if (c == '[') return parse_array();
        if (c == '"') return parse_string();
        if (c == '-' || std::isdigit(c)) return parse_number();
        if (c == 't' || c == 'f' || c == 'n') return parse_literal();
        return Value(); // null fallback
    }

    Value parse_object() {
        Value val;
        val.type = Type::Object;
        get(); // consume '{'
        
        while (true) {
            char c = peek();
            if (c == '}') {
                get(); // consume '}'
                break;
            }
            
            if (c == ',') {
                get(); // consume ','
                c = peek();
            }
            
            if (c != '"') {
                // error or unexpected token, break to avoid infinite loop
                break;
            }
            
            Value key_val = parse_string();
            skip_whitespace();
            
            char colon = get();
            if (colon != ':') {
                break; // error
            }
            
            Value item_val = parse_value();
            val.obj_val[key_val.str_val] = item_val;
        }
        return val;
    }

    Value parse_array() {
        Value val;
        val.type = Type::Array;
        get(); // consume '['

        while (true) {
            char c = peek();
            if (c == ']') {
                get(); // consume ']'
                break;
            }
            if (c == ',') {
                get(); // consume ','
                c = peek();
            }
            val.arr_val.push_back(parse_value());
        }
        return val;
    }

    Value parse_string() {
        Value val;
        val.type = Type::String;
        get(); // consume '"'
        
        std::string s;
        while (pos < src.size()) {
            char c = src[pos++];
            if (c == '"') {
                break;
            }
            if (c == '\\') {
                if (pos < src.size()) {
                    char esc = src[pos++];
                    if (esc == '"') s += '"';
                    else if (esc == '\\') s += '\\';
                    else if (esc == '/') s += '/';
                    else if (esc == 'b') s += '\b';
                    else if (esc == 'f') s += '\f';
                    else if (esc == 'n') s += '\n';
                    else if (esc == 'r') s += '\r';
                    else if (esc == 't') s += '\t';
                }
            } else {
                s += c;
            }
        }
        val.str_val = s;
        return val;
    }

    Value parse_number() {
        Value val;
        val.type = Type::Number;
        size_t start = pos;
        if (src[pos] == '-') {
            pos++;
        }
        while (pos < src.size() && (std::isdigit(src[pos]) || src[pos] == '.' || src[pos] == 'e' || src[pos] == 'E' || src[pos] == '+' || src[pos] == '-')) {
            pos++;
        }
        std::string num_str = src.substr(start, pos - start);
        try {
            val.num_val = std::stod(num_str);
        } catch (...) {
            val.num_val = 0.0;
        }
        return val;
    }

    Value parse_literal() {
        Value val;
        if (src.compare(pos, 4, "true") == 0) {
            val.type = Type::Bool;
            val.bool_val = true;
            pos += 4;
        } else if (src.compare(pos, 5, "false") == 0) {
            val.type = Type::Bool;
            val.bool_val = false;
            pos += 5;
        } else if (src.compare(pos, 4, "null") == 0) {
            val.type = Type::Null;
            pos += 4;
        }
        return val;
    }
};

Value parse(const std::string& src) {
    ParserInternal p(src);
    return p.parse();
}

} // namespace Json

namespace Parser {

// Helper to strip quotes and whitespace
static std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n\"");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n\"");
    return str.substr(first, (last - first + 1));
}

// Convert string to double safely
static double toDouble(const std::string& str) {
    std::string trimmed = trim(str);
    if (trimmed.empty()) return 0.0;
    try {
        return std::stod(trimmed);
    } catch (...) {
        return 0.0;
    }
}

// Convert string to uint32 safely
static uint32_t toUint32(const std::string& str) {
    std::string trimmed = trim(str);
    if (trimmed.empty()) return 0;
    try {
        if (trimmed.rfind("0x", 0) == 0 || trimmed.rfind("0X", 0) == 0) {
            return std::stoul(trimmed, nullptr, 16);
        }
        return std::stoul(trimmed);
    } catch (...) {
        return 0;
    }
}

// Convert string to bool safely
static bool toBool(const std::string& str) {
    std::string trimmed = trim(str);
    std::transform(trimmed.begin(), trimmed.end(), trimmed.begin(), [](unsigned char c){ return std::tolower(c); });
    return (trimmed == "true" || trimmed == "1" || trimmed == "yes");
}

// Helper to decode CAN hex data string to bytes
static std::vector<uint8_t> decodeHex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    std::string cleaned;
    for (char c : hex) {
        if (std::isxdigit(c)) {
            cleaned += c;
        }
    }
    for (size_t i = 0; i + 1 < cleaned.size(); i += 2) {
        std::string byteString = cleaned.substr(i, 2);
        uint8_t byte = (uint8_t)std::stoul(byteString, nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Splits CSV row by commas, acknowledging double quotes
std::vector<std::string> CSVParser::splitRow(const std::string& row, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    bool insideQuotes = false;
    for (size_t i = 0; i < row.size(); ++i) {
        char c = row[i];
        if (c == '"') {
            insideQuotes = !insideQuotes;
        } else if (c == delimiter && !insideQuotes) {
            tokens.push_back(token);
            token.clear();
        } else {
            token += c;
        }
    }
    tokens.push_back(token);
    return tokens;
}

std::vector<PiF::PiFEvent> CSVParser::parseFile(const std::string& filepath) {
    std::vector<PiF::PiFEvent> events;
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open CSV file " << filepath << std::endl;
        return events;
    }

    std::string line;
    if (!std::getline(file, line)) {
        return events;
    }

    std::vector<std::string> headers = splitRow(line, ',');
    std::map<std::string, size_t> headerMap;
    for (size_t i = 0; i < headers.size(); ++i) {
        std::string h = trim(headers[i]);
        std::transform(h.begin(), h.end(), h.begin(), [](unsigned char c){ return std::tolower(c); });
        headerMap[h] = i;
    }

    size_t lineNum = 1;
    while (std::getline(file, line)) {
        lineNum++;
        if (trim(line).empty()) continue;
        std::vector<std::string> row = splitRow(line, ',');
        
        auto getValue = [&](const std::string& key) -> std::string {
            auto it = headerMap.find(key);
            if (it != headerMap.end() && it->second < row.size()) {
                return trim(row[it->second]);
            }
            return "";
        };

        PiF::PiFEvent event;
        event.core.event_id = getValue("event_id");
        if (event.core.event_id.empty()) {
            event.core.event_id = "csv_evt_" + std::to_string(lineNum);
        }
        event.core.timestamp = toDouble(getValue("timestamp"));
        event.core.source_type = getValue("source_type");
        event.core.source_file = filepath;
        event.core.raw_reference = "Line " + std::to_string(lineNum);
        event.core.image_data = getValue("image_data");

        if (event.core.source_type == "bosch_cdr") {
            PiF::CDRPayload payload;
            payload.pre_crash_speed = toDouble(getValue("pre_crash_speed"));
            payload.delta_v = toDouble(getValue("delta_v"));
            payload.brake_status = toBool(getValue("brake_status"));
            payload.engine_rpm = toDouble(getValue("engine_rpm"));
            payload.brake_status_conflict = toBool(getValue("brake_status_conflict"));
            payload.brake_pressure_low = toBool(getValue("brake_pressure_low"));
            event.payload = payload;
            events.push_back(event);
        } else if (event.core.source_type == "berla_ive") {
            PiF::IVePayload payload;
            payload.infotainment_event = getValue("infotainment_event");
            payload.gps_coord = getValue("gps_coord");
            payload.device_paired = getValue("device_paired");
            event.payload = payload;
            events.push_back(event);
        } else if (event.core.source_type == "can_log") {
            PiF::CANPayload payload;
            payload.arbitration_id = toUint32(getValue("arbitration_id"));
            payload.dlc = (uint8_t)toUint32(getValue("dlc"));
            payload.bus_channel = getValue("bus_channel");
            
            std::string dataStr = getValue("data_bytes");
            // If dataStr is space separated list or direct hex
            if (dataStr.find(' ') != std::string::npos) {
                std::stringstream ss(dataStr);
                std::string byteStr;
                while (ss >> byteStr) {
                    payload.data_bytes.push_back((uint8_t)toUint32(byteStr));
                }
            } else {
                payload.data_bytes = decodeHex(dataStr);
            }
            payload.packet_injection = toBool(getValue("packet_injection"));
            payload.firmware_error_flag = toBool(getValue("firmware_error_flag"));
            payload.diagnostic_mode_active = toBool(getValue("diagnostic_mode_active"));
            payload.traction_loss = toBool(getValue("traction_loss"));
            event.payload = payload;
            events.push_back(event);
        }
    }
    return events;
}

std::vector<PiF::PiFEvent> JSONParser::parseFile(const std::string& filepath) {
    std::vector<PiF::PiFEvent> events;
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open JSON file " << filepath << std::endl;
        return events;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string src = buffer.str();

    Json::Value root = Json::parse(src);
    if (!root.is_array()) {
        // Try parsing as single object
        if (root.is_object()) {
            std::vector<Json::Value> arr;
            arr.push_back(root);
            Json::Value new_root;
            new_root.type = Json::Type::Array;
            new_root.arr_val = arr;
            root = new_root;
        } else {
            std::cerr << "Error: JSON is not an array or object in " << filepath << std::endl;
            return events;
        }
    }

    for (size_t i = 0; i < root.size(); ++i) {
        const Json::Value& item = root[i];
        if (!item.is_object()) continue;

        PiF::PiFEvent event;
        event.core.event_id = item["event_id"].get_string();
        if (event.core.event_id.empty()) {
            event.core.event_id = "json_evt_" + std::to_string(i + 1);
        }
        event.core.timestamp = item["timestamp"].get_double();
        event.core.source_type = item["source_type"].get_string();
        event.core.source_file = filepath;
        event.core.raw_reference = "Index " + std::to_string(i);
        event.core.image_data = item["image_data"].get_string();

        if (event.core.source_type == "bosch_cdr") {
            PiF::CDRPayload payload;
            payload.pre_crash_speed = item["pre_crash_speed"].get_double();
            payload.delta_v = item["delta_v"].get_double();
            payload.brake_status = item["brake_status"].get_bool();
            payload.engine_rpm = item["engine_rpm"].get_double();
            payload.brake_status_conflict = item["brake_status_conflict"].get_bool();
            payload.brake_pressure_low = item["brake_pressure_low"].get_bool();
            event.payload = payload;
            events.push_back(event);
        } else if (event.core.source_type == "berla_ive") {
            PiF::IVePayload payload;
            payload.infotainment_event = item["infotainment_event"].get_string();
            payload.gps_coord = item["gps_coord"].get_string();
            payload.device_paired = item["device_paired"].get_string();
            event.payload = payload;
            events.push_back(event);
        } else if (event.core.source_type == "can_log") {
            PiF::CANPayload payload;
            payload.arbitration_id = (uint32_t)item["arbitration_id"].get_double();
            payload.dlc = (uint8_t)item["dlc"].get_double();
            payload.bus_channel = item["bus_channel"].get_string();

            const Json::Value& dataVal = item["data_bytes"];
            if (dataVal.is_array()) {
                for (size_t d = 0; d < dataVal.size(); ++d) {
                    payload.data_bytes.push_back((uint8_t)dataVal[d].get_double());
                }
            } else if (dataVal.is_string()) {
                payload.data_bytes = decodeHex(dataVal.get_string());
            }

            payload.packet_injection = item["packet_injection"].get_bool();
            payload.firmware_error_flag = item["firmware_error_flag"].get_bool();
            payload.diagnostic_mode_active = item["diagnostic_mode_active"].get_bool();
            payload.traction_loss = item["traction_loss"].get_bool();
            event.payload = payload;
            events.push_back(event);
        }
    }

    return events;
}

std::vector<PiF::PiFEvent> parseLog(const std::string& filepath) {
    std::string ext = filepath.substr(filepath.find_last_of(".") + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c){ return std::tolower(c); });

    if (ext == "json") {
        JSONParser parser;
        return parser.parseFile(filepath);
    } else {
        // Fallback to CSV parser
        CSVParser parser;
        return parser.parseFile(filepath);
    }
}

} // namespace Parser
