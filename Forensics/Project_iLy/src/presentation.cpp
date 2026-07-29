#include "presentation.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>

namespace Presentation {

MarkdownGenerator::MarkdownGenerator() = default;

static std::string formatTimestamp(double ts) {
    // Return formatted timestamp or seconds as decimal
    std::stringstream ss;
    ss << std::fixed << std::setprecision(6) << ts;
    return ss.str();
}

static std::string hexStr(uint32_t val) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << val;
    return ss.str();
}

static std::string getEventDescription(const PiF::PiFEvent& ev) {
    if (ev.core.source_type == "bosch_cdr" && std::holds_alternative<PiF::CDRPayload>(ev.payload)) {
        auto cdr = std::get<PiF::CDRPayload>(ev.payload);
        std::stringstream ss;
        ss << "**EDR Snapshot**: Speed = " << cdr.pre_crash_speed << " mph, Delta-V = " << cdr.delta_v 
           << " mph, Brakes = " << (cdr.brake_status ? "ON" : "OFF") << ", RPM = " << cdr.engine_rpm;
        if (cdr.brake_status_conflict) {
            ss << " <span style='color:red;'>[BRAKE STATUS CONFLICT]</span>";
        }
        return ss.str();
    } else if (ev.core.source_type == "berla_ive" && std::holds_alternative<PiF::IVePayload>(ev.payload)) {
        auto ive = std::get<PiF::IVePayload>(ev.payload);
        std::stringstream ss;
        ss << "**Infotainment Event**: " << ive.infotainment_event;
        if (!ive.gps_coord.empty()) {
            ss << " (GPS: " << ive.gps_coord << ")";
        }
        if (!ive.device_paired.empty()) {
            ss << " (Paired Bluetooth: " << ive.device_paired << ")";
        }
        return ss.str();
    } else if (ev.core.source_type == "can_log" && std::holds_alternative<PiF::CANPayload>(ev.payload)) {
        auto can = std::get<PiF::CANPayload>(ev.payload);
        std::stringstream ss;
        ss << "**CAN Frame**: ID " << hexStr(can.arbitration_id) << " [DLC " << (int)can.dlc << "] data: ";
        for (uint8_t b : can.data_bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
        }
        if (can.packet_injection) {
            ss << "<span style='color:orange;'>[INJECTION ANOMALY]</span> ";
        }
        if (can.firmware_error_flag) {
            ss << "<span style='color:red;'>[FIRMWARE ERROR]</span> ";
        }
        if (can.diagnostic_mode_active) {
            ss << "<span style='color:red;'>[DIAG SESSION ACTIVE]</span> ";
        }
        if (can.traction_loss) {
            ss << "<span style='color:blue;'>[SLIP/TRACTION LOSS]</span> ";
        }
        return ss.str();
    }
    return "Unknown Event Type";
}

std::string MarkdownGenerator::generate(
    const Timeline::TimelineData& timeline,
    const Attribution::AttributionResult& attribution,
    const std::map<std::string, Hasher::FileHashes>& file_hashes,
    const std::string& engine_version
) {
    std::stringstream ss;

    // 1. Report Header
    ss << "# Project iLy - Incident Attribution Report\n\n";
    ss << "| Metadata Parameter | Value |\n";
    ss << "|---|---|\n";
    ss << "| **Report ID** | `" << attribution.attribution_id << "` |\n";
    ss << "| **Incident ID** | `" << attribution.incident_id << "` |\n";
    ss << "| **Attribution Version** | `" << engine_version << "` |\n";
    ss << "| **Generated At** | `" << attribution.generated_at << "` (Unix Epoch) |\n";
    ss << "| **Alignment Method** | `" << timeline.alignment_method << "` |\n";
    ss << "| **Time Window** | " << formatTimestamp(timeline.start_ts) << "s to " << formatTimestamp(timeline.end_ts) << "s (Duration: " 
       << std::fixed << std::setprecision(4) << (timeline.end_ts - timeline.start_ts) << "s) |\n\n";

    // 2. Non-Repudiation and File Hashes
    ss << "## 1. Input Files Integrity & Chain of Custody\n\n";
    ss << "The following cryptographic hashes verify the authenticity of the parsed inputs:\n\n";
    ss << "| Filename | MD5 Hash | SHA-256 Hash |\n";
    ss << "|---|---|---|\n";
    for (const auto& [filepath, hashes] : file_hashes) {
        size_t last_slash = filepath.find_last_of("/\\");
        std::string filename = (last_slash == std::string::npos) ? filepath : filepath.substr(last_slash + 1);
        ss << "| `" << filename << "` | `" << hashes.md5 << "` | `" << hashes.sha256 << "` |\n";
    }
    ss << "\n";

    // 3. Summary of Attribution
    ss << "## 2. Executive Summary\n\n";
    std::string cat = attribution.primary_attribution.category;
    std::transform(cat.begin(), cat.end(), cat.begin(), [](unsigned char c){ return std::toupper(c); });

    if (cat == "INCONCLUSIVE") {
        ss << "> [!WARNING]\n";
        ss << "> **PRIMARY ATTRIBUTION**: INCONCLUSIVE\n";
        ss << "> \n";
        ss << "> The attribution engine could not reliably determine the primary factor of this incident due to insufficient matching IoCs or high timing mismatch. Expert manual intervention is advised.\n\n";
    } else {
        ss << "> [!IMPORTANT]\n";
        ss << "> **PRIMARY ATTRIBUTION FACTOR**: **" << cat << "**\n";
        ss << "> \n";
        ss << "> **Confidence**: **" << std::fixed << std::setprecision(2) << (attribution.primary_attribution.confidence * 100) << "%**\n";
        ss << "> **Corroboration Tier**: **" << attribution.primary_attribution.corroboration_tier << "**\n\n";
    }

    // 4. Category Score Breakdown
    ss << "## 3. Policy & Score Breakdown\n\n";
    ss << "| Category | Normalized Score | Corroboration Tier | Active IoCs / Policies Triggers |\n";
    ss << "|---|---|---|---|\n";
    for (const auto& [name, score_res] : attribution.category_scores) {
        ss << "| " << name << " | **" << std::fixed << std::setprecision(4) << score_res.score << "** | " << score_res.corroboration_tier << " | ";
        if (score_res.contributing_matches.empty()) {
            ss << "*None*";
        } else {
            for (size_t i = 0; i < score_res.contributing_matches.size(); ++i) {
                ss << "`" << score_res.contributing_matches[i] << "`" << (i + 1 < score_res.contributing_matches.size() ? ", " : "");
            }
        }
        ss << " |\n";
    }
    ss << "\n";

    // 5. Timeline Narrative
    ss << "## 4. Narrative Timeline\n\n";
    ss << "Chronological sequence of reconciled and normalized events across inputs:\n\n";
    ss << "| Index | Original Timestamp | Adjusted Timestamp | Source | Event Narrative / Payload | Time Confidence |\n";
    ss << "|---|---|---|---|---|---|\n";
    for (const auto& te : timeline.ordered_events) {
        size_t last_slash = te.pif_event.core.source_file.find_last_of("/\\");
        std::string filename = (last_slash == std::string::npos) ? te.pif_event.core.source_file : te.pif_event.core.source_file.substr(last_slash + 1);

        ss << "| " << te.sequence_index << " | " << formatTimestamp(te.pif_event.core.timestamp) << "s | " 
           << formatTimestamp(te.adjusted_timestamp) << "s | `" << te.pif_event.core.source_type << "` (" << filename << ") | " 
           << getEventDescription(te.pif_event) << " | " << te.time_confidence << " |\n";
    }
    ss << "\n";

    // 6. Evidence Appendix
    ss << "## 5. Audit Trail & Raw Reference Logs\n\n";
    ss << "Detailed reference to files and logs triggers:\n\n";
    for (const auto& te : timeline.ordered_events) {
        bool has_payload = false;
        // Check if there are any specific warnings in payload (e.g. conflict flags or active flags)
        if (te.pif_event.core.source_type == "bosch_cdr" && std::holds_alternative<PiF::CDRPayload>(te.pif_event.payload)) {
            auto cdr = std::get<PiF::CDRPayload>(te.pif_event.payload);
            if (cdr.brake_status_conflict || cdr.brake_pressure_low) has_payload = true;
        } else if (te.pif_event.core.source_type == "can_log" && std::holds_alternative<PiF::CANPayload>(te.pif_event.payload)) {
            auto can = std::get<PiF::CANPayload>(te.pif_event.payload);
            if (can.packet_injection || can.firmware_error_flag || can.diagnostic_mode_active || can.traction_loss) has_payload = true;
        }

        if (has_payload) {
            ss << "* **Event ID**: `" << te.pif_event.core.event_id << "` | **File**: `" << te.pif_event.core.source_file << "` | **Ref**: `" 
               << te.pif_event.core.raw_reference << "`\n";
            ss << "  * *Raw Image Metadata*: `" << (te.pif_event.core.image_data.empty() ? "None" : te.pif_event.core.image_data) << "`\n";
        }
    }
    ss << "\n";

    // 7. Confidence & Caveats Notes
    ss << "## 6. Confidence Notes & Expert Guidance\n\n";
    ss << "* **Corroboration Tier Mapping**:\n";
    ss << "  * **High**: Matches observed across multiple independent digital sources (e.g., EDR cross-checked with CAN traffic) confirming the incident vector.\n";
    ss << "  * **Medium**: Indicators present in a single source with high confidence but lacking direct hardware/cross-file confirmation.\n";
    ss << "  * **Low**: Low confidence scores or weak timeline alignment with high discrepancy bounds.\n";
    ss << "* **Forensic Notice**: This report serves as an investigation assistant to organize incident timeline evidence and flag anomaly indicators. Results must be verified by a certified vehicle forensics specialist.\n";

    return ss.str();
}

void MarkdownGenerator::saveToFile(const std::string& filepath, const std::string& content) {
    std::ofstream file(filepath);
    if (file.is_open()) {
        file << content;
        std::cout << "Report successfully written to: " << filepath << std::endl;
    } else {
        std::cerr << "Error: Could not open output path: " << filepath << std::endl;
    }
}

} // namespace Presentation
