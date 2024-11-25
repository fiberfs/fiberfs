fiber_test "JSON multi"

json_multi '[' 'null' '' '  ' ']'
json_multi 't' 'ru' '' 'e' ' '
json_multi '[' 'n' 'ul' 'l   ,  fa' 'ls' 'e]' '   '
json_multi '123' '45.' '678' '' '9' ' '
json_multi '123' '.' '5'
json_multi '123'
