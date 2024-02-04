#pragma once
#include <string>
#include <set>

class Rule {
  public:
    Rule( std::string name ) //
        : name( name ) {
    }
    std::string name;
    std::set<std::string> deps;
    bool operator==( const Rule &otherRule ) const {
        return this->name == otherRule.name;
    }

    bool operator<( const Rule &otherRule ) const {
        return this->name < otherRule.name;
    }

    struct HashFunction {
        size_t operator( )( const Rule &rule ) const {
            return std::hash<std::string>( )( rule.name );
        }
    };
};