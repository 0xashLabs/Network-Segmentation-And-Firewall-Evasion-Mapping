#ifndef PIF_HPP
#define PIF_HPP

#include <string>
#include <vector>
#include <variant>
#include <cstdint>

namespace PiF {

struct CDRPayload {
    double pre_crash_speed = 0.0;       // mph or km/h
    double delta_v = 0.0;               // change in velocity
    bool brake_status = false;          // true = pressed, false = released
    double engine_rpm = 0.0;
    bool brake_status_conflict = false; // Flag computed during cross-check
    bool brake_pressure_low = false;
};

struct IVePayload {
    std::string infotainment_event;     // e.g., "Phone Connected", "Door Opened"
    std::string gps_coord;              // "lat, lon"
    std::string device_paired;          // MAC address or device name
};

struct CANPayload {
    uint32_t arbitration_id = 0;
    uint8_t dlc = 0;
    std::vector<uint8_t> data_bytes;
    std::string bus_channel;            // e.g., "vcan0", "can0"
    bool packet_injection = false;      // Flag computed during security policy checks
    bool firmware_error_flag = false;   // Flag indicating software firmware error
    bool diagnostic_mode_active = false;// Diagnostic mode session active during motion
    bool traction_loss = false;         // Electronic stability control slipped
    bool brake_status_conflict = false; // Flag computed during cross-check
};

struct PiFEventCore {
    std::string event_id;
    double timestamp = 0.0;             // Normalized epoch timestamp (seconds)
    std::string source_type;            // "bosch_cdr" | "berla_ive" | "can_log"
    std::string source_file;            // Original source file this event came from
    std::string raw_reference;          // Traceable link (original line number or record index)
    std::string image_data;             // Placeholder field for images/media (unused by v1 logic)
};

struct PiFEvent {
    PiFEventCore core;
    std::variant<std::monostate, CDRPayload, IVePayload, CANPayload> payload;
};

} // namespace PiF

#endif // PIF_HPP
