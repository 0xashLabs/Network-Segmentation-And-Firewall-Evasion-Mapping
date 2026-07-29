#include "attribution.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <iostream>
#include <ctime>

namespace Attribution {

static std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

static std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream ss(str);
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

static bool isDividerLine(const std::string& line) {
    std::string clean = trim(line);
    if (clean.empty()) return false;
    for (char c : clean) {
        if (c != '|' && c != '-' && c != ':' && c != ' ' && c != '\t') {
            return false;
        }
    }
    return true;
}

AttributionEngine::AttributionEngine(const std::string& policies_filepath) {
    loadPolicies(policies_filepath);
}

void AttributionEngine::loadPolicies(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open policies file: " << filepath << std::endl;
        return;
    }

    std::string line;
    std::cout << "Attribution Engine: Loading policies from " << filepath << "..." << std::endl;
    while (std::getline(file, line)) {
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;
        if (!trimmed.starts_with('|') || !trimmed.ends_with('|')) continue;
        if (isDividerLine(trimmed)) continue;

        std::vector<std::string> cols = split(trimmed, '|');
        // Clean columns
        for (auto& col : cols) {
            col = trim(col);
        }

        // Standard markdown split produces empty strings at first and last positions
        // e.g. | col1 | col2 | -> ["", "col1", "col2", ""]
        if (cols.size() < 9) continue;

        std::string ioc_id = cols[1];
        if (ioc_id == "ioc_id" || ioc_id.empty()) continue; // skip header row

        PolicyRule rule;
        rule.ioc_id = ioc_id;
        rule.category = cols[2];
        rule.match_type = cols[3];
        rule.trigger_field = cols[4];
        rule.op = cols[5];
        rule.trigger_value = cols[6];
        rule.description = cols[7];
        try {
            rule.match_confidence = std::stod(cols[8]);
        } catch (...) {
            rule.match_confidence = 0.5;
        }

        rules.push_back(rule);
        std::cout << " - Loaded rule: " << rule.ioc_id << " (" << rule.category << ")" << std::endl;
    }
}

void AttributionEngine::runCrossChecks(Timeline::TimelineData& timeline) {
    // Perform cross-checks between EDR (bosch_cdr) and CAN (can_log)
    for (auto& te_cdr : timeline.ordered_events) {
        if (te_cdr.pif_event.core.source_type == "bosch_cdr" &&
            std::holds_alternative<PiF::CDRPayload>(te_cdr.pif_event.payload)) {
            
            auto& cdr = std::get<PiF::CDRPayload>(te_cdr.pif_event.payload);

            // Scan for CAN log events within 1.0 second
            for (auto& te_can : timeline.ordered_events) {
                if (te_can.pif_event.core.source_type == "can_log" &&
                    std::holds_alternative<PiF::CANPayload>(te_can.pif_event.payload)) {
                    
                    double diff = std::abs(te_cdr.adjusted_timestamp - te_can.adjusted_timestamp);
                    if (diff <= 1.0) {
                        auto& can = std::get<PiF::CANPayload>(te_can.pif_event.payload);
                        
                        // Scenario 1: Brake mismatch check (EDR says brakes on, CAN logs show brakes off)
                        // If CAN data bytes indicate no brake (e.g. byte 0 == 0x00 or a flag is false)
                        // but CDR reports brake_status == true.
                        // Or if CAN payload explicitly has brake status false (or we simulate it via data bytes)
                        // For our mock test: if CAN payload has arbitration ID 0x200 (brake signal) 
                        // and its data bytes[0] == 0 (no brake) but EDR has brake_status == true.
                        bool can_brake = true;
                        if (can.arbitration_id == 0x200 && !can.data_bytes.empty()) {
                            can_brake = (can.data_bytes[0] != 0);
                        }

                        if (cdr.brake_status && !can_brake) {
                            cdr.brake_status_conflict = true;
                            can.brake_status_conflict = true; // flag both
                        }
                    }
                }
            }
        }
    }
}

bool AttributionEngine::evaluateRuleOnEvent(const PolicyRule& rule, const Timeline::TimelineEvent& te) {
    const auto& ev = te.pif_event;

    if (ev.core.source_type == "bosch_cdr" && std::holds_alternative<PiF::CDRPayload>(ev.payload)) {
        auto cdr = std::get<PiF::CDRPayload>(ev.payload);
        if (rule.trigger_field == "brake_status_conflict") {
            return cdr.brake_status_conflict && (rule.trigger_value == "true" || rule.trigger_value == "1");
        }
        if (rule.trigger_field == "delta_v") {
            if (rule.op == "greater_than") {
                return cdr.delta_v > std::stod(rule.trigger_value);
            }
            if (rule.op == "less_than") {
                return cdr.delta_v < std::stod(rule.trigger_value);
            }
        }
        if (rule.trigger_field == "brake_pressure_low") {
            return cdr.brake_pressure_low && (rule.trigger_value == "true" || rule.trigger_value == "1");
        }
    }

    if (ev.core.source_type == "can_log" && std::holds_alternative<PiF::CANPayload>(ev.payload)) {
        auto can = std::get<PiF::CANPayload>(ev.payload);
        if (rule.trigger_field == "packet_injection") {
            return can.packet_injection && (rule.trigger_value == "true" || rule.trigger_value == "1");
        }
        if (rule.trigger_field == "firmware_error_flag") {
            return can.firmware_error_flag && (rule.trigger_value == "true" || rule.trigger_value == "1");
        }
        if (rule.trigger_field == "diagnostic_mode_active") {
            return can.diagnostic_mode_active && (rule.trigger_value == "true" || rule.trigger_value == "1");
        }
        if (rule.trigger_field == "traction_loss") {
            return can.traction_loss && (rule.trigger_value == "true" || rule.trigger_value == "1");
        }
    }

    return false;
}

AttributionResult AttributionEngine::evaluate(Timeline::TimelineData& timeline) {
    AttributionResult res;
    res.attribution_id = "attr_" + std::to_string(std::time(nullptr));
    res.incident_id = timeline.timeline_id;
    res.generated_at = (uint64_t)std::time(nullptr);

    // 1. Execute cross-checks
    runCrossChecks(timeline);

    // 2. Track contributing sources for corroboration mapping
    // Maps category -> set of unique source files contributing to the category
    std::map<std::string, std::vector<std::string>> category_sources;
    std::map<std::string, std::vector<IoCMatch>> category_matches;

    // Initialize category scores map
    std::vector<std::string> cats = {"cyber", "mechanical", "environmental", "software"};
    for (const auto& c : cats) {
        res.category_scores[c] = CategoryResult{0.0, "low", {}};
    }

    // 3. Match rules against all events
    for (const auto& te : timeline.ordered_events) {
        for (const auto& rule : rules) {
            if (evaluateRuleOnEvent(rule, te)) {
                IoCMatch match;
                match.event_id = te.pif_event.core.event_id;
                match.ioc_id = rule.ioc_id;
                match.ioc_category = rule.category;
                match.match_type = rule.match_type;
                match.description = rule.description;
                match.match_confidence = rule.match_confidence;

                category_matches[rule.category].push_back(match);

                // Add source file to track corroboration
                auto& src_list = category_sources[rule.category];
                if (std::find(src_list.begin(), src_list.end(), te.pif_event.core.source_file) == src_list.end()) {
                    src_list.push_back(te.pif_event.core.source_file);
                }

                // Add contributing match ID to the result
                res.category_scores[rule.category].contributing_matches.push_back(rule.ioc_id);
            }
        }
    }

    // 4. Calculate scores per category and corroboration tier
    for (const auto& c : cats) {
        auto& cat_res = res.category_scores[c];
        const auto& matches = category_matches[c];
        
        if (matches.empty()) {
            cat_res.score = 0.0;
            cat_res.corroboration_tier = "low";
            continue;
        }

        // Probabilistic combination: Score = 1 - PRODUCT(1 - Confidence * TimeFactor)
        double product = 1.0;
        for (const auto& match : matches) {
            // Find the time confidence factor of the matched event
            double time_factor = 0.7; // default medium
            for (const auto& te : timeline.ordered_events) {
                if (te.pif_event.core.event_id == match.event_id) {
                    if (te.time_confidence == "high") time_factor = 1.0;
                    else if (te.time_confidence == "medium") time_factor = 0.7;
                    else if (te.time_confidence == "low") time_factor = 0.4;
                    break;
                }
            }
            product *= (1.0 - match.match_confidence * time_factor);
        }
        cat_res.score = 1.0 - product;

        // Determine corroboration tier
        size_t source_count = category_sources[c].size();
        if (source_count >= 2) {
            cat_res.corroboration_tier = "high";
        } else if (source_count == 1 && cat_res.score >= 0.7) {
            cat_res.corroboration_tier = "medium";
        } else {
            cat_res.corroboration_tier = "low";
        }
    }

    // 5. Select primary attribution
    double highest_score = -1.0;
    std::string primary_cat = "inconclusive";

    for (const auto& [cat, score_res] : res.category_scores) {
        if (score_res.score > highest_score) {
            highest_score = score_res.score;
            primary_cat = cat;
        }
    }

    // If highest score is very low, mark as inconclusive
    if (highest_score < 0.20) {
        primary_cat = "inconclusive";
        highest_score = 0.0;
    }

    res.primary_attribution.category = primary_cat;
    res.primary_attribution.confidence = highest_score;
    
    if (primary_cat != "inconclusive") {
        res.primary_attribution.corroboration_tier = res.category_scores[primary_cat].corroboration_tier;
    } else {
        res.primary_attribution.corroboration_tier = "low";
    }

    return res;
}

} // namespace Attribution
