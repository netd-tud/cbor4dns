"""
Provides the trie data structure.
"""

import enum
import pprint
import typing


class TrieSearchResult(enum.Enum):
    """
    Results for a Trie::search.
    """
    NOT_FOUND = 0
    PREFIX_FOUND = 1
    MATCH_FOUND = 2


class StringTrie:
    """A trie

    Based on https://stackoverflow.com/a/11016430

    >>> Trie()
    {}
    >>> Trie(["foo", "bar", "foobar"])
    """
    _end_marker = None
    _trie_type = str

    def __init__(self, strings=None):
        self.root = {}
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
            current_node = current_node[char]
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
            current_node = current_node.setdefault(char, {})
        current_node[self._end_marker] = {}

    def _remove(self, node, string, depth=0):
        if not node:
            return None
        if depth == len(string):
            if self._end_marker in node:
                del node[self._end_marker]
            if not node:
                del node
                node = None
            return node
        key = string[depth]
        node[key] = self._remove(node[key], string, depth + 1)
        if not node[key]:
            del node[key]
        if not node:
            del node
            node = None
        return node

    def remove(self, string):
        self._remove(self.root, string)


class BytesTrie(StringTrie):
    _trie_type = bytes
