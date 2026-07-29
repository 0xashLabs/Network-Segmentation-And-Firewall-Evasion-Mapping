#include "hasher.hpp"
#include "parser.hpp"
#include "timeline.hpp"
#include "attribution.hpp"
#include "presentation.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <map>

void printUsage() {
    std::cout << "Project iLy - Accident Attribution Engine (v1)\n";
    std::cout << "Usage: ily [options] <log_file_1> [log_file_2] ... [log_file_N]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --policies <path>   Path to policies.md file (default: policies.md)\n";
    std::cout << "  --output <path>     Path to write the report (default: report.md)\n";
    std::cout << "  --tolerance <sec>   Time tolerance for alignment in seconds (default: 1.0)\n";
    std::cout << "  --help              Show this help message\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::vector<std::string> input_files;
    std::string policies_path = "policies.md";
    std::string output_path = "report.md";
    double tolerance = 1.0;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        } else if (arg == "--policies") {
            if (i + 1 < argc) {
                policies_path = argv[++i];
            } else {
                std::cerr << "Error: --policies option requires a path argument.\n";
                return 1;
            }
        } else if (arg == "--output") {
            if (i + 1 < argc) {
                output_path = argv[++i];
            } else {
                std::cerr << "Error: --output option requires a path argument.\n";
                return 1;
            }
        } else if (arg == "--tolerance") {
            if (i + 1 < argc) {
                try {
                    tolerance = std::stod(argv[++i]);
                } catch (...) {
                    std::cerr << "Error: Invalid tolerance value. Must be a decimal number.\n";
                    return 1;
                }
            } else {
                std::cerr << "Error: --tolerance option requires a value argument.\n";
                return 1;
            }
        } else {
            // Treat as input file
            input_files.push_back(arg);
        }
    }

    if (input_files.empty()) {
        std::cerr << "Error: No input log files provided.\n";
        printUsage();
        return 1;
    }

    std::cout << "--------------------------------------------------\n";
    std::cout << "Project iLy - Starting Attribution Run\n";
    std::cout << "--------------------------------------------------\n";

    // 1. Compute Cryptographic Hashes for Non-Repudiation
    std::map<std::string, Hasher::FileHashes> file_hashes;
    std::vector<PiF::PiFEvent> all_events;

    for (const auto& filepath : input_files) {
        std::cout << "Hashing input file: " << filepath << std::endl;
        Hasher::FileHashes hashes = Hasher::hashFile(filepath);
        file_hashes[filepath] = hashes;

        std::cout << "Parsing log file: " << filepath << std::endl;
        std::vector<PiF::PiFEvent> file_events = Parser::parseLog(filepath);
        std::cout << " - Parsed " << file_events.size() << " events.\n";
        
        all_events.insert(all_events.end(), file_events.begin(), file_events.end());
    }

    if (all_events.empty()) {
        std::cerr << "Error: No events parsed from the input files.\n";
        return 1;
    }

    // 2. Timeline Construction & Timing Alignment
    std::cout << "Constructing normalized timeline with tolerance " << tolerance << "s...\n";
    Timeline::TimelineConstructor timeline_constructor(tolerance);
    Timeline::TimelineData timeline = timeline_constructor.construct(all_events);
    std::cout << " - Completed timeline: " << timeline.ordered_events.size() << " aligned events.\n";

    // 3. Attribution & IoC Rule Matching
    std::cout << "Initializing Attribution Engine with " << policies_path << "...\n";
    Attribution::AttributionEngine engine(policies_path);
    Attribution::AttributionResult attribution = engine.evaluate(timeline);
    
    std::cout << "\nAnalysis Result:\n";
    std::cout << " - Primary Attribution: " << attribution.primary_attribution.category << "\n";
    std::cout << " - Confidence Vector: " << attribution.primary_attribution.confidence << "\n";
    std::cout << " - Corroboration Tier: " << attribution.primary_attribution.corroboration_tier << "\n";

    // 4. Report Generation
    std::cout << "\nGenerating Markdown report...\n";
    Presentation::MarkdownGenerator reporter;
    std::string report_content = reporter.generate(timeline, attribution, file_hashes);
    reporter.saveToFile(output_path, report_content);

    std::cout << "--------------------------------------------------\n";
    std::cout << "Attribution Run Completed Successfully.\n";
    std::cout << "--------------------------------------------------\n";

    return 0;
}
