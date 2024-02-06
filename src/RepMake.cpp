#include <iostream>

#include "RepMakeLexer.h"
#include "RepMakeParser.h"
#include "antlr4-runtime.h"
#include "rules.hpp"

using namespace antlr4;
using namespace antlr4::tree;

std::pair<char*, std::streampos> readEntireFile(const char* inputFile);

bool addContextToMap(RepMakeParser::RepmakeContext* context, std::map<std::string, Rule>& all_rules_map, std::unordered_set<std::string>& targets_to_run);

int main(int argc, const char* argv[]) {
    std::unordered_set<std::string> targets_to_run;
    for (int i = 1; i < argc; i++) {
        targets_to_run.insert(std::string(argv[i]));
    }

    std::map<std::string, Rule> all_rules_map;
    bool error_flag = false;
    const char* inputFiles[] = {"RepMake", "RepDep.d"};
    for (const char* inputFile : inputFiles) {
        auto inputBuffer = readEntireFile(inputFile);
        ANTLRInputStream input(inputBuffer.first, inputBuffer.second);
        delete[] inputBuffer.first;
        input.name = inputFile;
        RepMakeLexer lexer(&input);
        CommonTokenStream tokens(&lexer);
        RepMakeParser parser(&tokens);
        if (parser.getNumberOfSyntaxErrors() != 0) {
            return 1;
        }
        auto context = parser.repmake();
        if (parser.repmake() == NULL) {
            return 1;
        }
        error_flag |= addContextToMap(context, all_rules_map, targets_to_run);
    }
    for (auto& element : all_rules_map) {
        std::string rule_name = element.first;
        Rule& rule = element.second;
        std::unordered_set<Rule*>& triggers = rule.triggers;
        for (std::string dep_str : rule.deps_str) {
            if (dep_str == rule_name) {
                std::cerr << "Error: \"" << dep_str << "\" depends on itself." << std::endl;
            }
            auto pos = all_rules_map.find(dep_str);
            if (pos != all_rules_map.end()) {
                // The depepdency is a rule
                Rule* dep = &pos->second;
                rule.dep_rules.insert(dep);
                dep->triggers.emplace(&rule);
            }
            rule.dep_files.emplace(dep_str);
        }
    }
    if (error_flag) {
        return -1;
    }

    if (false) {
        for (const auto& element : all_rules_map) {
            std::string rule_name = element.first;
            const Rule& rule = element.second;
            std::cout << rule_name << ": ";
            for (const Rule* const triggers : rule.triggers) {
                std::cout << " " << triggers->name;
            }
            std::cout << std::endl;
            // for (const std::string& tasks : rule.tasks) {
            //     std::cout << "            " << tasks << std::endl;
            // }
        }
    }
    Rule::runTasksInOrder(targets_to_run, all_rules_map);

    std::ofstream rep_dep_out("RepDep.d");
    for (const auto& element : all_rules_map) {
        std::string rule_name = element.first;
        const Rule& rule = element.second;
        rep_dep_out << rule.name << ":";
        for (const auto& dep : rule.dep_files) {
            rep_dep_out << " " << dep;
        }
        rep_dep_out << std::endl
                    << std::endl;
    }
    rep_dep_out.close();
    // std::cout << "Success!" << std::endl;
    return 0;
}

std::pair<char*, std::streampos> readEntireFile(const char* inputFile) {
    std::ifstream stream;
    stream.open(inputFile);
    stream.seekg(0, std::ios::end);
    std::streampos fileSize = stream.tellg();
    fileSize += 1;
    stream.seekg(0, std::ios::beg);

    char* buffer = new char[fileSize];
    // Add a new line since i couldn't figure out how to write my rule without needing start of line token.
    // Use \n instead of \n so it doesn't offset the line count (kinda hacky, but works).
    buffer[0] = '\r';
    stream.read(&buffer[1], fileSize);
    return {buffer, fileSize};

    // auto vocab = lexer.getVocabulary();

    // if (false) {
    //     lexer.reset();
    //     // Print out the tokens.
    //     std::vector<std::unique_ptr<Token>> tokens = lexer.getAllTokens();
    //     for (const std::unique_ptr<Token>& token : tokens) {
    //         if (token->getChannel() != Token::DEFAULT_CHANNEL) {
    //             continue;
    //         }
    //         // std::cout << token->getChannel();
    //         if (token->getType() == RepMakeLexer::NEW_LINE) {
    //             std::cout << " NEW_LINE" << std::endl;
    //         } else {
    //             std::cout << " " << lexer.getErrorDisplay(vocab.getDisplayName(token->getType())) << " " << lexer.getErrorDisplay(token->getText()) << std::endl;
    //         }
    //     }
    //     lexer.reset();
    // }

    // return parser;
}

bool addContextToMap(RepMakeParser::RepmakeContext* context, std::map<std::string, Rule>& all_rules_map, std::unordered_set<std::string>& targets_to_run) {
    std::vector<RepMakeParser::Rep_make_ruleContext*> rules = context->rep_make_rule();
    bool error_flag = false;
    // Add the data into our structure.

    for (RepMakeParser::Rep_make_ruleContext* const rule : rules) {
        std::string rule_name = rule->rule_name()->IDENTIFIER()->getText();
        if (targets_to_run.empty()) {
            targets_to_run.insert(rule_name);
        }
        auto deps_list = rule->dependency_list();

        std::unordered_set<std::string> deps_str;
        if (deps_list != NULL) {
            std::vector<RepMakeParser::Rule_nameContext*> deps = deps_list->rule_name();
            for (RepMakeParser::Rule_nameContext* dep : deps) {
                deps_str.insert(dep->IDENTIFIER()->getText());
            }
        }

        std::vector<std::string> tasks_vector;
        RepMakeParser::TasksContext* tasks = rule->tasks();
        bool hasTasks = tasks != NULL;
        if (hasTasks) {
            for (RepMakeParser::TaskContext* task : tasks->task()) {
                tasks_vector.emplace_back(task->getText());
            }
        }

        auto success = all_rules_map.insert({rule_name, {rule_name, deps_str, tasks_vector}});
        if (!success.second) {
            // Failed to insert because duplicate.
            Rule& existing = success.first->second;
            if (existing.tasks.size() != 0 && hasTasks) {
                std::cerr << "Error: Rule defined with multiple tasks: \"" << rule_name << "\"" << std::endl;
                error_flag = true;
            } else {
                if (hasTasks) {
                    existing.tasks = std::move(tasks_vector);
                }
            }
            existing.deps_str.insert(deps_str.begin(), deps_str.end());
            std::cout << "";
        }
    }
    return error_flag;
}