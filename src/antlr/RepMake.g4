grammar RepMake;

// Lex
COMMENT: '#' .*? NEW_LINE -> channel(HIDDEN);
IDENT: NEW_LINE (SPACES | '\t'+);
SPACES: ' '+;
NEW_LINE: '\n'+;
IDENTIFIER: [a-zA-Z0-9_]+;

// Parse
repmake: (rep_make_rule)+ EOF;

rep_make_rule: rule_name ':' dependency_list NEW_LINE? tasks? NEW_LINE?;

dependency_list: rule_name ( ',' rule_name)*?;

tasks: (IDENT task)+;

task: (IDENTIFIER | SPACES)+;
rule_name: SPACES? IDENTIFIER SPACES?;