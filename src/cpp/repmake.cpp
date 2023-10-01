#include <iostream>

#include "RepMakeLexer.h"
#include "RepMakeParser.h"
#include "antlr4-runtime.h"

using namespace antlr4;

int main(int argc, const char* argv[]) {
    std::ifstream stream;
    if (argc != 2) {
        std::cerr << "Usage:" << argv[0] << "[RepMake file name]" << std::endl;
    }
    const char* inputFile = argv[1];
    stream.open(inputFile);

    ANTLRInputStream input(stream);
    RepMakeLexer lexer(&input);
    CommonTokenStream tokens(&lexer);
    RepMakeParser parser(&tokens);
    parser.setErrorHandler(std::shared_ptr<BailErrorStrategy>(new BailErrorStrategy()));
    RepMakeParser::RepmakeContext* context;
    try {
        context = parser.repmake();
    } catch (ParseCancellationException* e) {
        std::cerr << "Error parseing: " << inputFile << std::endl;
        exit(1);
    }
    std::vector<RepMakeParser::Rep_make_ruleContext*> rules = context->rep_make_rule();
    for (RepMakeParser::Rep_make_ruleContext* rule : rules) {
        std::string rule_name = rule->rule_name()->SYMBOL()->getText();
        std::cout << "Name:" << rule_name << std::endl;
    }

    // std::vector<Rep_make_ruleContext*> rep_make_rules;

    // tree::TerminalNode* symb = assignment->SYMBOL();
    // std::string symbol_str = symb->getSymbol()->getText();
    // tree::TerminalNode* value_str = assignment->value()->STRING();
    // tree::TerminalNode* value_symb = assignment->value()->SYMBOL();
    // if (value_str != NULL) {
    //     std::cout << symbol_str << " str " << value_str->getSymbol()->getText() << std::endl;
    // } else if (value_symb != NULL) {
    //     std::cout << symbol_str << " symb " << value_symb->getSymbol()->getText() << std::endl;
    // }
    // string value_str = assignment->value()->STRING()->getSymbol()->getText();
    // std::cout << symbol_str << " value_str: " << value_str << " value_symb: " << value_symb << std::endl;

    return 0;
}