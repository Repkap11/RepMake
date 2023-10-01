#include <iostream>

#include "antlr4-runtime.h"
#include "RepmakeLexer.h"
#include "RepmakeParser.h"

using namespace std;
using namespace antlr4;

int main(int argc, const char* argv[]) {
    std::ifstream stream;
    stream.open("RepMake");
    
    ANTLRInputStream input(stream);
    RepmakeLexer lexer(&input);
    CommonTokenStream tokens(&lexer);
    RepmakeParser parser(&tokens);    

    RepmakeParser::AssignmentContext* tree = parser.assignment();

    return 0;
}