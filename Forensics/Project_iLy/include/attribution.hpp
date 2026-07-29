#ifndef ATTRIBUTION_HPP
#define ATTRIBUTION_HPP

#include "timeline.hpp"
#include <string>
#include <vector>
#include <map>

namespace Attribution {

struct IoCMatch {
    std::string event_id;
    std::string ioc_id;
    std::string ioc_category; // "cyber" | "mechanical" | "environmental" | "software"
    std::string match_type;   // "exact" | "pattern" | "heuristic"
    std::string description;
    double match_confidence = 0.0;
};

struct CategoryResult {
    double score = 0.0;
    std::string corroboration_tier; // "high" | "medium" | "low"
    std::vector<std::string> contributing_matches; // list of ioc_ids
};

struct AttributionResult {
    std::string attribution_id;
    std::string incident_id;
    uint64_t generated_at = 0;
    std::map<std::string, CategoryResult> category_scores;
    
    struct PrimaryAttribution {
        std::string category; // "cyber" | "mechanical" | "environmental" | "software" | "inconclusive"
        double confidence = 0.0;
        std::string corroboration_tier;
    } primary_attribution;
};

struct PolicyRule {
    std::string ioc_id;
    std::string category;
    std::string match_type;
    std::string trigger_field;
    std::string op; // "equals" | "greater_than" | "less_than"
    std::string trigger_value;
    std::string description;
    double match_confidence = 0.0;
};

class AttributionEngine {
public:
    explicit AttributionEngine(const std::string& policies_filepath);
    AttributionResult evaluate(Timeline::TimelineData& timeline);

private:
    std::vector<PolicyRule> rules;
    void loadPolicies(const std::string& filepath);
    void runCrossChecks(Timeline::TimelineData& timeline);
    bool evaluateRuleOnEvent(const PolicyRule& rule, const Timeline::TimelineEvent& te);
};

} // namespace Attribution

#endif // ATTRIBUTION_HPP
