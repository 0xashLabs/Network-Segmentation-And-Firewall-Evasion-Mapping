#ifndef TIMELINE_HPP
#define TIMELINE_HPP

#include "pif.hpp"
#include <string>
#include <vector>

namespace Timeline {

struct AnchorPoint {
    std::string event_id;
    std::string anchor_type; // e.g. "impact", "ignition", "pairing"
    std::string confidence;  // "high" | "medium" | "low"
    double original_ts = 0.0;
};

struct TimelineEvent {
    PiF::PiFEvent pif_event;
    size_t sequence_index = 0;
    double adjusted_timestamp = 0.0;
    std::string time_confidence; // "high" | "medium" | "low"
};

struct TimelineData {
    std::string timeline_id;
    double start_ts = 0.0;
    double end_ts = 0.0;
    std::vector<AnchorPoint> anchor_points;
    std::string alignment_method; // "anchored" | "tolerance_band_fallback"
    std::vector<TimelineEvent> ordered_events;
};

class TimelineConstructor {
public:
    explicit TimelineConstructor(double tolerance_seconds = 1.0);
    TimelineData construct(const std::vector<PiF::PiFEvent>& all_events);

private:
    double tolerance_band;
    std::vector<AnchorPoint> detectAnchors(const std::vector<PiF::PiFEvent>& events);
};

} // namespace Timeline

#endif // TIMELINE_HPP
