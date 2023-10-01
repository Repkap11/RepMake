grammar repmake;

assignment: symbol '=' value EOF;

symbol: char_sequence;
value: string;

string: '"' char_sequence '"';

char_sequence: (CHAR)*;

CHAR: [a-z]+;