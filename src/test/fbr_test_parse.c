/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/fbr_test.h"

#include <stdlib.h>

#define _TRIM_STR_LEFT(s, len)				\
	while ((len) > 0 && (s)[0] <= ' ') {		\
		(s)++;					\
		(len)--;				\
	}

#define _TRIM_STR_RIGHT(s, len)				\
	while ((len) > 0 && (s)[(len) - 1] <= ' ') {	\
		(len)--;				\
		(s)[(len)] = '\0';			\
	}

#define	_TRIM_STR(s, len)				\
	do {						\
		_TRIM_STR_LEFT(s, len);			\
		_TRIM_STR_RIGHT(s, len);		\
	} while (0)

void
fbr_test_unescape(struct fbr_test_param *param)
{
	size_t offset, i;

	assert(param);
	assert(param->value);
	// TODO remove
	assert(param->len == strlen(param->value));

	if (param->v_const) {
		return;
	}

	for (i = 0, offset = 0; i < param->len; i++) {
		if (param->value[i] != '\\') {
			if (offset) {
				param->value[i - offset] = param->value[i];
			}

			continue;
		}

		assert(i < param->len - 1);

		switch (param->value[i + 1]) {
			case '\\':
				param->value[i - offset] = '\\';
				offset++;
				i++;
				continue;
			case '\"':
				param->value[i - offset] = '\"';
				offset++;
				i++;
				continue;
			case 'n':
				param->value[i - offset] = '\n';
				offset++;
				i++;
				continue;
			case 'r':
				param->value[i - offset] = '\r';
				offset++;
				i++;
				continue;
			case 't':
				param->value[i - offset] = '\t';
				offset++;
				i++;
				continue;
			default:
				i++;
				continue;
		}
	}

	if (offset) {
		assert(offset < param->len);
		param->value[param->len - offset] = '\0';
		param->len -= offset;
	}
}

int
fbr_test_readline(struct fbr_test *test, size_t append_len)
{
	char *ret;
	size_t oldlen, i;

	fbr_test_ok(test);
	assert(test->line_raw);
	assert(test->line_raw_len > 1);
	assert(append_len < test->line_raw_len);
	assert(test->ft_file);

	test->line_buf_len = 0;
	test->line_buf = NULL;

	if (append_len) {
		test->lines_multi++;
	} else {
		test->lines_multi = 0;
	}

	if (test->line_raw_len > append_len + 1) {
		test->line_raw[test->line_raw_len - 2] = '\n';

		ret = fgets(test->line_raw + append_len, test->line_raw_len - append_len,
			test->ft_file);

		if (!ret && !append_len) {
			return 0;
		}
	}

	// Didn't reach end of line, expand and read more
	while (test->line_raw[test->line_raw_len - 2] &&
	    test->line_raw[test->line_raw_len - 2] != '\n') {
		oldlen = test->line_raw_len;
		test->line_raw_len *= 2;
		assert(test->line_raw_len / 2 == oldlen);

		test->line_raw = realloc(test->line_raw, test->line_raw_len);
		assert(test->line_raw);

		test->line_raw[test->line_raw_len - 2] = '\n';

		if (!fgets(test->line_raw + oldlen - 1, (test->line_raw_len - oldlen) + 1,
		    test->ft_file)) {
			break;
		}
	}

	test->lines++;
	test->line_buf = test->line_raw;
	test->line_buf_len = strlen(test->line_buf);

	_TRIM_STR(test->line_buf, test->line_buf_len);

	if (test->line_buf_len == 0 || *test->line_buf == '#') {
		return fbr_test_readline(test, 0);
	}

	if (test->line_buf[test->line_buf_len - 1] == '\\') {
		i = 1;
		while (i < test->line_buf_len &&
		    test->line_buf[test->line_buf_len - i - 1] == '\\') {
			i++;
		}

		if (i % 2 == 1) {
			// Read the next line
			test->line_buf[test->line_buf_len - 1] = '\0';
			test->line_buf_len--;

			_TRIM_STR_RIGHT(test->line_buf, test->line_buf_len);

			if (test->line_buf_len) {
				i = test->line_buf - test->line_raw + test->line_buf_len;
				assert(i < test->line_raw_len);

				return fbr_test_readline(test, i);
			} else {
				return fbr_test_readline(test, 0);
			}
		}
	}

	//_test_unescape(test);

	return 1;
}

void
fbr_test_parse_cmd(struct fbr_test *test)
{
	struct fbr_test_cmdentry *cmd_entry;
	struct fbr_test_cmd *cmd;
	char *buf, *var;
	size_t i, len, count, start;
	int quote;

	fbr_test_ok(test);
	fbr_test_cmd_ok(&test->cmd);
	assert(test->line_buf);
	assert(test->line_buf_len);

	cmd = &test->cmd;
	chttp_ZERO(cmd);
	cmd->magic = FBR_TEST_CMD_MAGIC;
	cmd->name = test->line_buf;

	buf = test->line_buf;
	len = test->line_buf_len;
	start = 0;
	quote = 0;

	for (i = 0; i < len; i++) {
		if (quote && buf[i] == '\"') {
			count = 1;
			while (buf[i - count] == '\\') {
				count++;
			}

			if (count % 2 != 1) {
				continue;
			} else {
				assert(cmd->param_count);
				assert(cmd->params[cmd->param_count - 1].value[0] == '\"');

				quote = 0;
				buf[i] = ' ';
				cmd->params[cmd->param_count - 1].value += 1;
				start++;
			}
		}
		if (!quote && buf[i] <= ' ' ) {
			buf[i] = '\0';

			if (cmd->param_count) {
				cmd->params[cmd->param_count - 1].len = i - start;
			}

			i++;

			while (i < len && buf[i] <= ' ') {
				i++;
			}

			if (i == len) {
				i++;
				break;
			}

			fbr_test_ERROR(cmd->param_count >= FBR_TEST_MAX_PARAMS,
				"too many parameters");

			cmd->params[cmd->param_count].value = &buf[i];
			cmd->param_count++;

			start = i;

			if (buf[i] == '\"') {
				quote = 1;
			}
		}
	}

	fbr_test_ERROR(quote, "ending quote not found");

	if (i == len && cmd->param_count) {
		cmd->params[cmd->param_count - 1].len = i - start;
	}

	if (test->verbocity == FBR_LOG_VERY_VERBOSE) {
		fbr_test_log(test->context, FBR_LOG_NONE, "%s (line %zu)",
			cmd->name, fbr_test_line_pos(test));
	} else {
		fbr_test_log(test->context, FBR_LOG_NONE, "%s", cmd->name);
	}

	for (i = 0; i < cmd->param_count; i++) {
		// TODO remove
		assert(cmd->params[i].len == strlen(cmd->params[i].value));

		if (cmd->params[i].value[0] == '$' && cmd->params[i].value[1] == '$') {
			cmd->params[i].value += 1;
		} else if (cmd->params[i].value[0] == '$') {
			var = cmd->params[i].value;

			fbr_test_log(test->context, FBR_LOG_VERY_VERBOSE, "Var: %s", var);

			cmd_entry = fbr_test_cmds_get(test, var);
			fbr_test_ERROR(!cmd_entry || !cmd_entry->is_var,
				"variable %s not found (line %zu)", var, fbr_test_line_pos(test));
			assert(cmd_entry->var_func);

			buf = cmd_entry->var_func(test->context);

			cmd->params[i].value = buf;
			cmd->params[i].len = strlen(buf);
			cmd->params[i].v_const = 1;
		}

		fbr_test_log(test->context, FBR_LOG_VERY_VERBOSE, "Arg: %s",
			cmd->params[i].value);
	}
}
