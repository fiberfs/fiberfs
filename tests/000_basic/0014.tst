fiber_test Variables

set_var1 "ab" "c" 123
equal $var1 "abc123"

random_range 10 99

set_var2 "test: " $var1 ' ' $random
print $var2

set_var1
equal $var1 "$var3"

set_var5 "\"" $var3 "\""
set_var4 '""'
equal $var4 $var5
