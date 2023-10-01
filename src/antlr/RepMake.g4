grammar RepMake;

repmake: (rep_make_rule | comment)+ EOF;

comment: '#' ~'\n'* '\n'*;

// Rules and dependicies
rep_make_rule:
	RULE_NAME ':' dependency_list '\n'+ ('\n' | TASK)*;

dependency_list: RULE_NAME ( ',' RULE_NAME)*?;
RULE_NAME: SYMBOL;
SYMBOL: [a-zA-Z0-9_]+;

// Tasks
TASK: '\t'+ (SYMBOL | ' ')+;

WHITESPACE: (' ')+ -> skip;