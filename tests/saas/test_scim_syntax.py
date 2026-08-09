from __future__ import annotations

import pytest

from saas.control_plane.scim_syntax import (
    ScimSyntaxError,
    parse_scim_filter,
    parse_scim_patch_path,
)


def test_filter_parser_supports_comparisons_literals_schema_and_value_path() -> None:
    expression = parse_scim_filter(
        "urn:ietf:params:scim:schemas:core:2.0:Group:members"
        '[(value gt "1000") and not (value eq null)]'
    )

    assert expression.operator == "valuePath"
    assert expression.attribute == "members"
    assert expression.schema == "urn:ietf:params:scim:schemas:core:2.0:Group"
    inner = expression.operands[0]
    assert inner.operator == "and"
    assert inner.operands[0].operator == "gt"
    assert inner.operands[0].value == "1000"
    assert inner.operands[1].operator == "not"
    assert inner.operands[1].operands[0].value is None

    number = parse_scim_filter("displayName ge 2.5")
    assert number.operator == "ge"
    assert number.value == 2.5


def test_patch_path_parser_supports_filtered_sub_attribute_and_rejects_bad_grammar() -> None:
    path = parse_scim_patch_path('members[(value sw "2819") or value pr].value')
    assert path.attribute == "members"
    assert path.sub_attribute == "value"
    assert path.value_filter is not None
    assert path.value_filter.operator == "or"

    with pytest.raises(ScimSyntaxError) as nested:
        parse_scim_patch_path('members[value[value eq "nested"]].value')
    assert nested.value.scim_type == "invalidPath"

    with pytest.raises(ScimSyntaxError) as trailing:
        parse_scim_filter('displayName gt "A" trailing')
    assert trailing.value.scim_type == "invalidFilter"
