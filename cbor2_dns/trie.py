"""
Provides the trie data structure.
"""

import enum
import itertools
import re
import pprint


class TrieSearchResult(enum.Enum):
    """
    Results for a Trie::search.
    """
    NOT_FOUND = 0
    PREFIX_FOUND = 1
    MATCH_FOUND = 2


class TrieNode(dict):
    def iter_children(self):
        for k in self.keys():
            yield k

    def get_child(self, child):
        return self[child]

    def add_child(self, child):
        return self.setdefault(child, type(self)())

    def set_child(self, child, subtree):
        self[child] = subtree
        return subtree

    def has_child(self, child):
        return child in self

    def remove_child(self, child):
        del self[child]


class CountingTrieNode(TrieNode):
    def __init__(self):
        self.count = 0

    def add_child(self, child):
        res = super().add_child(child)
        res.count += 1
        return res

    def remove_child(self, child):
        if hasattr(self[child], "count"):
            self[child].count -= 1
            if not self[child].count:
                super().remove_child(child)
        else:
            super().remove_child(child)


class BaseTrie:
    """A trie

    Based on https://stackoverflow.com/a/11016430

    >>> Trie()
    {}
    >>> Trie(["foo", "bar", "foobar"])
    """
    _end_marker = None
    _trie_type = str
    _trie_node_class = TrieNode

    def __init__(self, strings=None):
        self.root = self._trie_node_class()
        if strings:
            for string in strings:
                self.insert(string)

    def __str__(self):
        return pprint.pformat(self.root)

    def __eq__(self, other):
        return self.root == other.root

    def __contains__(self, string) -> bool:
        return self.search(string) == TrieSearchResult.MATCH_FOUND

    def search(self, string) -> TrieSearchResult:
        """
        Check if a string or a prefix for that string is in the trie.

        :param string: a string
        :type string: str

        :raises TypeError: if string is not a str
        """
        if not isinstance(string, self._trie_type):
            raise TypeError(f"string={string} must be {self._trie_type.__name__}")
        current_node = self.root
        for char in string:
            if char not in current_node:
                return TrieSearchResult.NOT_FOUND
            current_node = current_node.get_child(char)
        if self._end_marker in current_node:
            return TrieSearchResult.MATCH_FOUND
        return TrieSearchResult.PREFIX_FOUND

    def insert(self, string):
        """
        Insert a string into the trie.

        :param string: a string
        :type string: str

        :raises TypeError: if string is not a str
        """
        if not isinstance(string, self._trie_type):
            raise TypeError(f"string={string} must be {self._trie_type.__name__}")
        current_node = self.root
        for char in string:
            current_node = current_node.add_child(char)
        current_node.add_child(self._end_marker)

    def _remove(self, node, string, depth=0):
        if depth == len(string):
            if node.has_child(self._end_marker):
                node.remove_child(self._end_marker)
            if not node:
                node = None
            return node
        key = string[depth]
        node.set_child(key, self._remove(node.get_child(key), string, depth + 1))
        if not node.get_child(key):
            node.remove_child(key)
        if not node:
            node = None
        return node

    def remove(self, string):
        self._remove(self.root, string)


class StringTrie(BaseTrie):
    pass


class BytesTrie(BaseTrie):
    _trie_type = bytes


class CountingBaseTrie(BaseTrie):
    _trie_node_class = CountingTrieNode


class CountingStringTrie(StringTrie, CountingBaseTrie):
    pass


class CountingBytesTrie(BytesTrie, CountingBaseTrie):
    pass
