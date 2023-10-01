#include <iostream>

#include "RepMakeLexer.h"
#include "RepMakeParser.h"
#include "antlr4-runtime.h"
#include "rules.hpp"

using namespace antlr4;
using namespace antlr4::tree;

int main(int argc, const char* argv[]) {
    std::ifstream stream;
    if (argc != 2) {
        std::cerr << "Usage:" << argv[0] << "[RepMake file name]" << std::endl;
    }
    const char* inputFile = argv[1];
    stream.open(inputFile);

    ANTLRInputStream input(stream);
    input.name = inputFile;
    RepMakeLexer lexer(&input);
    if (true) {
        auto vocab = lexer.getVocabulary();
        std::vector<std::unique_ptr<Token>> tokens = lexer.getAllTokens();
        for (std::unique_ptr<Token>& token : tokens) {
            if (token->getChannel() != Token::DEFAULT_CHANNEL) {
                continue;
            }
            // std::cout << token->getChannel();
            if (token->getType() == RepMakeLexer::NEW_LINE) {
                std::cout << " NEW_LINE" << std::endl;
            } else {
                std::cout << " " << lexer.getErrorDisplay(vocab.getDisplayName(token->getType())) << " " << lexer.getErrorDisplay(token->getText()) << std::endl;
            }
        }
        lexer.reset();
    }

    CommonTokenStream tokens(&lexer);
    RepMakeParser parser(&tokens);
    RepMakeParser::RepmakeContext* context = parser.repmake();

    if (parser.getNumberOfSyntaxErrors() != 0) {
        return 1;
    }
    // std::unordered_map<std::string, std::pair<std::unordered_set<std::string>, std::vector<std::string>>> all_rules_str;
    std::unordered_map<std::string, Rule> all_rules_map;

    std::vector<RepMakeParser::Rep_make_ruleContext*> rules = context->rep_make_rule();
    bool error_flag = false;
    for (RepMakeParser::Rep_make_ruleContext* rule : rules) {
        std::string rule_name = rule->rule_name()->IDENTIFIER()->getText();
        std::vector<RepMakeParser::Rule_nameContext*> deps = rule->dependency_list()->rule_name();
        RepMakeParser::TasksContext* tasks = rule->tasks();
    }

    for (auto rule : rules) {
        auto dependency_rules = rule->dependency_list()->rule_name();

        std::string rule_name = rule->rule_name()->IDENTIFIER()->getText();
        for (auto dependency : dependency_rules) {
            std::string dep_name = dependency->IDENTIFIER()->getText();
            if (dep_name == rule_name) {
                std::cerr << "Error: \"" << dep_name << "\" depends on itself." << std::endl;
            }
            auto pos = all_rules_map.find(dep_name);
            if (pos == all_rules_map.end()) {
                std::cerr << "Error: Dependency \"" << dep_name << "\" not defined in rule \"" << rule_name << "\"" << std::endl;
                error_flag = true;
            }
        }
    }
    if (error_flag) {
        return -1;
    }
    // for (auto rule : rules) {
    //     RepMakeParser::TasksContext* tasks = rule->tasks();
    //     if (tasks == NULL) {
    //         continue;
    //     }
    //     for (RepMakeParser::TaskContext* task : tasks->task()) {
    //         std::cout << "Task:" << task->getText() << std::endl;
    //     }
    // }

    for (auto element : all_rules_map) {
        // std::string rule_name = element.first;
        Rule rule = std::move(element.second);
        std::unordered_set<Rule*>& deps = rule.deps;
        for (std::string dep_str : rule.deps_str) {
            deps.emplace(&all_rules_map.find(dep_str)->second);
        }
    }
    std::cout << "Success!" << std::endl;
    return 0;
}