#include <iostream>

#include "RepMakeLexer.h"
#include "RepMakeParser.h"
#include "antlr4-runtime.h"

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
    {
        auto vocab = lexer.getVocabulary();
        std::vector<std::unique_ptr<Token>> tokens = lexer.getAllTokens();
        for (std::unique_ptr<Token>& token : tokens) {
            if (token->getChannel() != Token::DEFAULT_CHANNEL){
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
    std::set<std::string> all_rules;
    auto rules = context->rep_make_rule();
    bool error_flag = false;
    for (auto rule : rules) {
        std::string rule_name = rule->rule_name()->getText();
        bool duplicate = !all_rules.insert(rule_name).second;
        if (duplicate) {
            std::cerr << "Error: Duplicate rule defined: \"" << rule_name << "\"" << std::endl;
            error_flag = true;
        }
    }
    for (auto rule : rules) {
        auto dependency_rules = rule->dependency_list()->rule_name();

        std::string rule_name = rule->rule_name()->getText();
        for (auto dependency : dependency_rules) {
            std::string dep_name = dependency->getText();
            if (dep_name == rule_name) {
                std::cerr << "Error: \"" << dep_name << "\" depends on itself." << std::endl;
            }
            auto pos = all_rules.find(dep_name);
            if (pos == all_rules.end()) {
                std::cerr << "Error: Dependency \"" << dep_name << "\" not defined in rule \"" << rule_name << "\"" << std::endl;
                error_flag = true;
            }
        }
    }
    if (error_flag) {
        return -1;
    }
    for (auto rule : rules) {
        auto tasks = rule->task();
        for (auto task : tasks) {
            std::cout << "Task:" << task->getText() << std::endl;
        }
    }
    std::cout << "Success!" << std::endl;
    return 0;
}