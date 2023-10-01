grammar RepMake;

// Lex
COMMENT: '#' .*? NEW_LINE -> channel(HIDDEN);
IDENT: NEW_LINE (' ' | '\t')+;
SPACE: ' ' -> channel(HIDDEN);
NEW_LINE: '\n'+;
IDENTIFIER: [a-zA-Z0-9_]+;



// Parse
repmake: (rep_make_rule | COMMENT)+ EOF;

rep_make_rule:
	rule_name ':' dependency_list NEW_LINE+ (NEW_LINE | task)*;

dependency_list: rule_name ( ',' rule_name)*?;

task: '\t' identifier_list;
rule_name: IDENTIFIER;
identifier_list: (IDENTIFIER ' '?)+;