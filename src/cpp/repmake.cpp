#include <iostream>

#include "RepMakeLexer.h"
#include "RepMakeParser.h"
#include "antlr4-runtime.h"
#include "rules.hpp"

using namespace antlr4;
using namespace antlr4::tree;

int main(int argc, const char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage:" << argv[0] << "[RepMake file name]" << std::endl;
    }
    const char* inputFile = argv[1];

    std::ifstream stream;
    stream.open(inputFile);
    stream.seekg(0, std::ios::end);
    std::streampos fileSize = stream.tellg();
    fileSize += 1;
    stream.seekg(0, std::ios::beg);

    char* buffer = new char[fileSize];
    buffer[0] = '\n';
    stream.read(&buffer[1], fileSize);

    ANTLRInputStream input(buffer, fileSize);
    input.name = inputFile;
    RepMakeLexer lexer(&input);
    auto vocab = lexer.getVocabulary();

    if (true) {
        lexer.reset();
        // Print out the tokens.
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
    // TokenStreamRewriter rewriter(&tokens);
    // rewriter.insertBefore(RepMakeLexer::NEW_LINE, "\n");
    // TokenStream* ts = rewriter.getTokenStream();
    // Token* firstToken = ts->get(0);
    // std::cout << "First Token:" << lexer.getErrorDisplay(vocab.getDisplayName(firstToken->getType()));
    // RepMakeParser parser(ts);
    RepMakeParser parser(&tokens);
    RepMakeParser::RepmakeContext* context = parser.repmake();

    if (parser.getNumberOfSyntaxErrors() != 0) {
        return 1;
    }
    // std::unordered_map<std::string, std::pair<std::unordered_set<std::string>, std::vector<std::string>>> all_rules_str;
    std::unordered_map<std::string, Rule> all_rules_map;

    std::vector<RepMakeParser::Rep_make_ruleContext*> rules = context->rep_make_rule();
    bool error_flag = false;
    // Add the data into our structure.

    for (RepMakeParser::Rep_make_ruleContext* const rule : rules) {
        std::string rule_name = rule->rule_name()->IDENTIFIER()->getText();
        auto deps_list = rule->dependency_list();

        std::unordered_set<std::string> deps_set;
        if (deps_list != NULL) {
            std::vector<RepMakeParser::Rule_nameContext*> deps = deps_list->rule_name();
            for (RepMakeParser::Rule_nameContext* dep : deps) {
                deps_set.insert(dep->IDENTIFIER()->getText());
            }
        }

        std::vector<std::string> tasks_vector;
        RepMakeParser::TasksContext* tasks = rule->tasks();
        if (tasks != NULL) {
            for (RepMakeParser::TaskContext* task : tasks->task()) {
                tasks_vector.emplace_back(task->getText());
            }
        }

        bool duplicate = !all_rules_map.insert({rule_name, {rule_name, std::move(deps_set), std::move(tasks_vector)}}).second;
        if (duplicate) {
            std::cerr << "Error: Duplicate rule defined: \"" << rule_name << "\"" << std::endl;
            error_flag = true;
        }
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
            if (pos == all_rules_map.end()) {
                std::cerr << "Error: Dependency \"" << dep_str << "\" not defined in rule \"" << rule_name << "\"" << std::endl;
                error_flag = true;
            }
            Rule* dep = &all_rules_map.find(dep_str)->second;
            dep->triggers.emplace(&rule);
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
    Rule::runTasksInOrder(all_rules_map);

    // std::cout << "Success!" << std::endl;
    return 0;
}