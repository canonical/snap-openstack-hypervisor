# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import click

VALUE_FORMAT = "value"
JSON_FORMAT = "json"
JSON_INDENT_FORMAT = "json-indent"
TABLE_FORMAT = "table"

click_option_format = click.option(
    "-f",
    "--format",
    default=JSON_FORMAT,
    type=click.Choice([VALUE_FORMAT, JSON_FORMAT, JSON_INDENT_FORMAT]),
    help="Output format",
)
