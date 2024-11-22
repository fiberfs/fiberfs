fiber_test "json bad"

json_fail ''
json_fail '{'
json_fail '[}'
json_fail '{true}'
json_fail 'nul'
json_fail 'true false'
