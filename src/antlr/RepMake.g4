grammar RepMake;

// Lex

BLOCK_COMMENET: '/*' .*? '*/' -> channel(HIDDEN);
LINE_COMMENT: '//' ~[\r\n]* -> channel(HIDDEN);
// HWS: [ \t]* -> channel(HIDDEN);

COMMENT: '#' ~( '\r' | '\n')* -> channel(HIDDEN);
IDENT: NEW_LINE (SPACES | '\t'+);
SPACES: ' '+;
NEW_LINE: [\r\n\f]+;
IDENTIFIER: [a-zA-Z0-9_]+;

// Parse
repmake: (rep_make_rule)* (IDENT)* EOF;

rep_make_rule:
	rule_name ':' dependency_list? NEW_LINE? tasks? NEW_LINE?;

dependency_list: rule_name ( ',' rule_name)*?;

tasks: (IDENT task)+;

task: (IDENTIFIER | SPACES)+;
rule_name: IDENTIFIER SPACES?;