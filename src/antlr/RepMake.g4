grammar RepMake;

// Lex

LINE_COMMENT: '//' ~[\r\n]* -> channel(HIDDEN);
// HWS: [ \t]* -> channel(HIDDEN);

COMMENT: '#' ~( '\r' | '\n')* -> channel(HIDDEN);
IDENT: NEW_LINE (SPACES | '\t'+);

IDENTIFIER: [a-zA-Z0-9_]+;

NEW_LINE: [\r?\n];
SPACES: ' '+;
TASK_CHARS: .+?;

// Parse
repmake: (rep_make_rule | IDENT | NEW_LINE | SPACES)* EOF;

rep_make_rule:
	NEW_LINE rule_name SPACES? ':' SPACES? dependency_list? IDENT? tasks? NEW_LINE?;

dependency_list: rule_name ( ',' rule_name)*?;

tasks: (IDENT task)+;

task: (IDENTIFIER | SPACES | TASK_CHARS | ':')+;
rule_name: IDENTIFIER SPACES?;