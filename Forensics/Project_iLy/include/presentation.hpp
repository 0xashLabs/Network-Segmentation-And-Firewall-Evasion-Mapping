#ifndef PRESENTATION_HPP
#define PRESENTATION_HPP

#include "timeline.hpp"
#include "attribution.hpp"
#include "hasher.hpp"
#include <string>
#include <vector>
#include <map>

namespace Presentation {

class MarkdownGenerator {
public:
    MarkdownGenerator();
    std::string generate(
        const Timeline::TimelineData& timeline,
        const Attribution::AttributionResult& attribution,
        const std::map<std::string, Hasher::FileHashes>& file_hashes,
        const std::string& engine_version = "v1.0.0"
    );

    void saveToFile(const std::string& filepath, const std::string& content);
};

} // namespace Presentation

#endif // PRESENTATION_HPP
