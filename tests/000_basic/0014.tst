fiber_test Variables

set var1 "ab" "c" 123
equal $var1 "abc123"

random_range 10 99

set var2 "test: " $var1 ' ' $random
print $var2

set var1
set var3 ""
equal $var1 "$var3"

set var5 "\"" $var3 "\""
set var4 '""'
equal $var4 $var5

set abc 123
print $abc

set empty
print $empty

set abc xyz
print $abc
