fiber_test "Bad json tests"

json_fail ''
json_fail '  '
json_fail '{'
json_fail '[}'
json_fail '{true}'
json_fail 'nul'
json_fail 'true false'
json_fail '[true,]'
json_fail '[,]'
json_fail '[[[]],]'
json_fail '{,}'
json_fail '{:}'
