# pylint: disable=missing-function-docstring,missing-module-docstring


import pytest

import cbor4dns.trie


def test_trie_node():
    node = cbor4dns.trie.TrieNode()
    node.add_child("b")
    assert list(node.iter_children()) == ["b"]
    assert not node.has_child("a")
    assert node.get_child("a") is None
    assert node.has_child("b")
    assert node.get_child("b") == cbor4dns.trie.TrieNode()
    node.remove_child("a")
    assert list(node.iter_children()) == ["b"]
    node.remove_child("b")
    assert not list(node.iter_children())


def test_counting_trie_node():
    node = cbor4dns.trie.CountingTrieNode()
    node.add_child("b")
    assert list(node.iter_children()) == ["b"]
    node.add_child("b")
    assert list(node.iter_children()) == ["b"]
    assert not node.has_child("a")
    assert node.get_child("a") is None
    assert node.has_child("b")
    assert node.get_child("b") == cbor4dns.trie.CountingTrieNode()
    node.remove_child("a")
    assert list(node.iter_children()) == ["b"]
    node.remove_child("b")
    assert list(node.iter_children()) == ["b"]
    node.remove_child("b")
    assert not list(node.iter_children())


def test_string_trie_init():
    assert repr(cbor4dns.trie.StringTrie()) == "<StringTrie: []>"
    assert str(cbor4dns.trie.StringTrie(["foo", "bar", "foobar"])) == (
        """{'b': {'a': {'r': {None: {}}}},
 'f': {'o': {'o': {None: {}, 'b': {'a': {'r': {None: {}}}}}}}}"""
    )


def test_string_trie_insert():
    trie = cbor4dns.trie.StringTrie()
    assert str(trie) == "{}"
    trie.insert("testing")
    assert str(trie) == "{'t': {'e': {'s': {'t': {'i': {'n': {'g': {None: {}}}}}}}}}"
    assert trie == cbor4dns.trie.StringTrie(["testing"])
    with pytest.raises(TypeError):
        trie.insert(1)
    with pytest.raises(TypeError):
        trie.insert(1)


def test_string_trie_search():
    trie = cbor4dns.trie.StringTrie()
    assert trie.search("test") == cbor4dns.trie.TrieSearchResult.NOT_FOUND
    assert trie.search("testing") == cbor4dns.trie.TrieSearchResult.NOT_FOUND
    trie.insert("testing")
    assert trie.search("test") == cbor4dns.trie.TrieSearchResult.PREFIX_FOUND
    assert trie.search("testing") == cbor4dns.trie.TrieSearchResult.MATCH_FOUND
    trie.insert("test")
    assert trie.search("test") == cbor4dns.trie.TrieSearchResult.MATCH_FOUND
    assert trie.search("testing") == cbor4dns.trie.TrieSearchResult.MATCH_FOUND
    with pytest.raises(TypeError):
        trie.search(1)


def test_string_trie_in():
    trie = cbor4dns.trie.StringTrie(["testing"])
    assert "foo" not in trie
    assert "test" not in trie
    assert "testing" in trie
    trie.insert("test")
    assert "foo" not in trie
    assert "test" in trie
    assert "testing" in trie


def test_string_trie_remove():
    trie = cbor4dns.trie.StringTrie(["foo", "bar", "foobar"])
    assert "test" not in trie
    assert "foo" in trie
    assert "bar" in trie
    assert "foobar" in trie
    trie.remove("foox")
    # trie should be unchanged
    assert "test" not in trie
    assert "foo" in trie
    assert "bar" in trie
    assert "foobar" in trie
    trie.remove("foob")
    # trie should be unchanged
    assert "test" not in trie
    assert "foo" in trie
    assert "bar" in trie
    assert "foobar" in trie
    trie.remove("foo")
    assert "test" not in trie
    assert "foo" not in trie
    assert "bar" in trie
    assert "foobar" in trie
    trie.remove("bar")
    assert "test" not in trie
    assert "foo" not in trie
    assert "bar" not in trie
    assert "foobar" in trie


def test_string_trie_iter():
    trie = cbor4dns.trie.StringTrie(["foo", "bar", "foobar"])
    expected = {"b", "ba", "bar", "f", "fo", "foo", "foob", "fooba", "foobar"}
    for string in trie:
        assert string in expected
        expected.remove(string)
    assert not expected


def exp_root_children(trie, root_children, root_children_counts):
    root_childs = 0
    count_checked = {c: False for c in root_children}
    for child in trie.root.iter_children():
        assert child in root_children
        for exp_child in root_children:
            if child == exp_child:
                assert trie.root[child].count == root_children_counts[child]
                count_checked[child] = True
        assert count_checked[child]
        root_childs += 1
    assert root_childs == len(root_children)


def test_counting_string_trie_remove():
    trie = cbor4dns.trie.CountingStringTrie(["foo", "bar", "bar", "foobar"])
    assert "test" not in trie
    assert "foo" in trie
    assert "bar" in trie
    assert "foobar" in trie
    exp_root_children(trie, ["f", "b"], {"f": 2, "b": 2})

    trie.remove("foox")
    # trie should be unchanged
    assert "test" not in trie
    assert "foo" in trie
    assert "bar" in trie
    assert "foobar" in trie
    exp_root_children(trie, ["f", "b"], {"f": 2, "b": 2})

    trie.remove("foob")
    # trie should be unchanged
    assert "test" not in trie
    assert "foo" in trie
    assert "bar" in trie
    assert "foobar" in trie
    exp_root_children(trie, ["f", "b"], {"f": 2, "b": 2})

    trie.remove("foo")
    assert "test" not in trie
    assert "foo" not in trie
    assert "bar" in trie
    assert "foobar" in trie
    exp_root_children(trie, ["f", "b"], {"f": 1, "b": 2})

    trie.remove("bar")
    assert "test" not in trie
    assert "foo" not in trie
    # we only removed one instance of "bar"
    assert "bar" in trie
    assert "foobar" in trie
    exp_root_children(trie, ["f", "b"], {"f": 1, "b": 1})

    trie.remove("bar")
    assert "test" not in trie
    assert "foo" not in trie
    # now bar is actually removed
    assert "bar" not in trie
    assert "foobar" in trie
    exp_root_children(trie, ["f"], {"f": 1})


def test_counting_string_trie_iter():
    trie = cbor4dns.trie.CountingStringTrie(["foo", "bar", "foobar"])
    expected = {
        (1, "b"),
        (1, "ba"),
        (1, "bar"),
        (2, "f"),
        (2, "fo"),
        (2, "foo"),
        (1, "foob"),
        (1, "fooba"),
        (1, "foobar"),
    }
    for string in trie:
        assert string in expected
        expected.remove(string)
    assert not expected


def test_bytes_trie_init():
    assert str(cbor4dns.trie.BytesTrie()) == "{}"
    assert str(cbor4dns.trie.BytesTrie([b"foo", b"bar", b"foobar"])) == (
        """{98: {97: {114: {None: {}}}},
 102: {111: {111: {None: {}, 98: {97: {114: {None: {}}}}}}}}"""
    )


def test_bytes_trie_insert():
    trie = cbor4dns.trie.BytesTrie()
    assert str(trie) == "{}"
    trie.insert(b"testing")
    assert str(trie) == "{116: {101: {115: {116: {105: {110: {103: {None: {}}}}}}}}}"
    assert trie == cbor4dns.trie.BytesTrie([b"testing"])
    with pytest.raises(TypeError):
        trie.insert(1)
    with pytest.raises(TypeError):
        trie.insert(1)


def test_bytes_trie_search():
    trie = cbor4dns.trie.BytesTrie()
    assert trie.search(b"test") == cbor4dns.trie.TrieSearchResult.NOT_FOUND
    assert trie.search(b"testing") == cbor4dns.trie.TrieSearchResult.NOT_FOUND
    trie.insert(b"testing")
    assert trie.search(b"test") == cbor4dns.trie.TrieSearchResult.PREFIX_FOUND
    assert trie.search(b"testing") == cbor4dns.trie.TrieSearchResult.MATCH_FOUND
    trie.insert(b"test")
    assert trie.search(b"test") == cbor4dns.trie.TrieSearchResult.MATCH_FOUND
    assert trie.search(b"testing") == cbor4dns.trie.TrieSearchResult.MATCH_FOUND
    with pytest.raises(TypeError):
        trie.search(1)


def test_bytes_trie_in():
    trie = cbor4dns.trie.BytesTrie([b"testing"])
    assert b"foo" not in trie
    assert b"test" not in trie
    assert b"testing" in trie
    trie.insert(b"test")
    assert b"foo" not in trie
    assert b"test" in trie
    assert b"testing" in trie


def test_counting_bytes_trie_iter():
    trie = cbor4dns.trie.CountingBytesTrie([b"foo", b"bar", b"foobar"])
    expected = {
        (1, b"b"),
        (1, b"ba"),
        (1, b"bar"),
        (2, b"f"),
        (2, b"fo"),
        (2, b"foo"),
        (1, b"foob"),
        (1, b"fooba"),
        (1, b"foobar"),
    }
    for string in trie:
        assert string in expected
        expected.remove(string)
    assert not expected
