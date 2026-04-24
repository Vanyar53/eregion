from annatar.safety.guard import check_resource_group, check_vm


def test_guard_allows_tagged_rg():
    result = check_resource_group({"sechaos-test": "true", "env": "test"})
    assert result.allowed


def test_guard_blocks_untagged_rg():
    result = check_resource_group({"env": "production"})
    assert not result.allowed
    assert "sechaos-test" in result.reason


def test_guard_blocks_empty_tags():
    result = check_resource_group({})
    assert not result.allowed


def test_guard_blocks_wrong_tag_value():
    result = check_resource_group({"sechaos-test": "false"})
    assert not result.allowed


def test_guard_tag_value_case_insensitive():
    result = check_resource_group({"sechaos-test": "True"})
    assert result.allowed


def test_guard_vm_allows_tagged():
    result = check_vm({"sechaos-test": "true"})
    assert result.allowed


def test_guard_vm_blocks_untagged():
    result = check_vm({"env": "prod"})
    assert not result.allowed
