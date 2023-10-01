grammar RepMake;

repmake: (rep_make_rule)+ EOF;

rep_make_rule: rule_name ':' dependency_list ';';

dependency_list: rule_name ( ',' rule_name )*? ;

rule_name: SYMBOL;

SYMBOL: [a-zA-Z0-9_]+;

WHITESPACE: ' ' -> skip;