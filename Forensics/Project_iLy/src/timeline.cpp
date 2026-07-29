#include "timeline.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <ctime>

namespace Timeline {

TimelineConstructor::TimelineConstructor(double tolerance_seconds)
    : tolerance_band(tolerance_seconds) {}

std::vector<AnchorPoint> TimelineConstructor::detectAnchors(const std::vector<PiF::PiFEvent>& events) {
    std::vector<AnchorPoint> anchors;
    for (const auto& ev : events) {
        if (ev.core.source_type == "bosch_cdr") {
            if (std::holds_alternative<PiF::CDRPayload>(ev.payload)) {
                auto p = std::get<PiF::CDRPayload>(ev.payload);
                if (std::abs(p.delta_v) > 0.01) {
                    AnchorPoint anchor;
                    anchor.event_id = ev.core.event_id;
                    anchor.anchor_type = "impact";
                    anchor.confidence = "high";
                    anchor.original_ts = ev.core.timestamp;
                    anchors.push_back(anchor);
                }
            }
        } else if (ev.core.source_type == "can_log") {
            if (std::holds_alternative<PiF::CANPayload>(ev.payload)) {
                auto p = std::get<PiF::CANPayload>(ev.payload);
                // Assume arbitration ID 0x150 is the airbag / collision signal on the CAN bus
                if (p.arbitration_id == 0x150) {
                    AnchorPoint anchor;
                    anchor.event_id = ev.core.event_id;
                    anchor.anchor_type = "impact";
                    anchor.confidence = "high";
                    anchor.original_ts = ev.core.timestamp;
                    anchors.push_back(anchor);
                }
            }
        } else if (ev.core.source_type == "berla_ive") {
            if (std::holds_alternative<PiF::IVePayload>(ev.payload)) {
                auto p = std::get<PiF::IVePayload>(ev.payload);
                if (p.infotainment_event == "Airbag Deployed" || p.infotainment_event == "Collision Detected") {
                    AnchorPoint anchor;
                    anchor.event_id = ev.core.event_id;
                    anchor.anchor_type = "impact";
                    anchor.confidence = "high";
                    anchor.original_ts = ev.core.timestamp;
                    anchors.push_back(anchor);
                }
            }
        }
    }
    return anchors;
}

TimelineData TimelineConstructor::construct(const std::vector<PiF::PiFEvent>& all_events) {
    TimelineData tl;
    tl.timeline_id = "timeline_" + std::to_string(std::time(nullptr));
    tl.ordered_events.clear();

    if (all_events.empty()) {
        tl.alignment_method = "tolerance_band_fallback";
        return tl;
    }

    // Detect anchors
    tl.anchor_points = detectAnchors(all_events);

    // Try to find if we can perform anchored alignment
    double edr_impact_ts = -1.0;
    double can_impact_ts = -1.0;
    double ive_impact_ts = -1.0;

    for (const auto& anchor : tl.anchor_points) {
        // Find the event in the original list
        for (const auto& ev : all_events) {
            if (ev.core.event_id == anchor.event_id) {
                if (ev.core.source_type == "bosch_cdr" && anchor.anchor_type == "impact") {
                    edr_impact_ts = anchor.original_ts;
                } else if (ev.core.source_type == "can_log" && anchor.anchor_type == "impact") {
                    can_impact_ts = anchor.original_ts;
                } else if (ev.core.source_type == "berla_ive" && anchor.anchor_type == "impact") {
                    ive_impact_ts = anchor.original_ts;
                }
            }
        }
    }

    double can_offset = 0.0;
    double ive_offset = 0.0;
    bool using_anchored = false;

    if (edr_impact_ts > 0.0) {
        if (can_impact_ts > 0.0) {
            can_offset = edr_impact_ts - can_impact_ts;
            using_anchored = true;
        }
        if (ive_impact_ts > 0.0) {
            ive_offset = edr_impact_ts - ive_impact_ts;
            using_anchored = true;
        }
    } else if (ive_impact_ts > 0.0 && can_impact_ts > 0.0) {
        can_offset = ive_impact_ts - can_impact_ts;
        using_anchored = true;
    }

    if (using_anchored) {
        tl.alignment_method = "anchored";
        std::cout << "Reconciliation Engine: Anchored alignment successful." << std::endl;
        if (can_offset != 0.0) {
            std::cout << " - CAN timestamp offset adjusted by: " << can_offset << " seconds." << std::endl;
        }
        if (ive_offset != 0.0) {
            std::cout << " - Telematics timestamp offset adjusted by: " << ive_offset << " seconds." << std::endl;
        }
    } else {
        tl.alignment_method = "tolerance_band_fallback";
        std::cout << "Reconciliation Engine: No shared anchors found. Falling back to absolute time tolerance band." << std::endl;
    }

    // Populate and adjust timestamps
    for (const auto& ev : all_events) {
        TimelineEvent te;
        te.pif_event = ev;
        te.adjusted_timestamp = ev.core.timestamp;

        if (ev.core.source_type == "can_log") {
            te.adjusted_timestamp += can_offset;
        } else if (ev.core.source_type == "berla_ive") {
            te.adjusted_timestamp += ive_offset;
        }

        // Compute time confidence
        if (using_anchored) {
            te.time_confidence = "high";
        } else {
            // Check if there are other source events within tolerance band
            bool close_to_other_source = false;
            for (const auto& other_ev : all_events) {
                if (other_ev.core.source_type != ev.core.source_type) {
                    double diff = std::abs(ev.core.timestamp - other_ev.core.timestamp);
                    if (diff <= tolerance_band) {
                        close_to_other_source = true;
                        break;
                    }
                }
            }
            te.time_confidence = close_to_other_source ? "medium" : "low";
        }

        tl.ordered_events.push_back(te);
    }

    // Sort events by adjusted timestamp
    std::sort(tl.ordered_events.begin(), tl.ordered_events.end(),
              [](const TimelineEvent& a, const TimelineEvent& b) {
                  if (a.adjusted_timestamp != b.adjusted_timestamp) {
                      return a.adjusted_timestamp < b.adjusted_timestamp;
                  }
                  return a.pif_event.core.event_id < b.pif_event.core.event_id;
              });

    // Assign sequence indices
    for (size_t i = 0; i < tl.ordered_events.size(); ++i) {
        tl.ordered_events[i].sequence_index = i;
    }

    // Compute incident window boundaries
    if (!tl.ordered_events.empty()) {
        tl.start_ts = tl.ordered_events.front().adjusted_timestamp;
        tl.end_ts = tl.ordered_events.back().adjusted_timestamp;
    }

    return tl;
}

} // namespace Timeline
