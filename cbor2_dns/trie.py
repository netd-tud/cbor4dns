"""
Provides the trie data structure.
"""

import enum
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

    @property
    def state(self):
        return True

    def get_child(self, child, child_state=None):
        return self.get(child, None)

    def add_child(self, child):
        return self.setdefault(child, type(self)())

    def has_child(self, child):
        return child in self

    def remove_child(self, child):
        if child in self:
            del self[child]


class CountingTrieNode(TrieNode):
    def __init__(self):
        self.count = 0

    @property
    def state(self):
        return self.count

    def get_child(self, child, child_state=None):
        if child_state is None:
            return super().get_child(child, child_state=child_state)
        child_node = super().get_child(child)
        if child_node and child_node.state != child_state:
            return None
        return child

    def add_child(self, child):
        res = super().add_child(child)
        res.count += 1
        return res

    def remove_child(self, child):
        if child in self and hasattr(self[child], "count"):
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

    def __repr__(self):
        return f"<{type(self).__name__}: {list(self)}>"

    def __eq__(self, other):
        return self.root == other.root

    def __contains__(self, string) -> bool:
        return self.search(string) == TrieSearchResult.MATCH_FOUND

    def _get_node_res(self, node, res):
        return res

    def _get_char(self, char):
        return char

    def __iter__(self):
        res_parts = []
        visited = []
        discovered = set()
        visited.append((self._trie_type(), self.root))
        res = self._trie_type()
        while visited:  # pragma: no cover
            char, node = visited.pop()
            if char == self._end_marker:
                try:
                    res = res_parts.pop()
                except IndexError:
                    # no more branches above this node, so just finish this iteration
                    return
            else:
                res += self._get_char(char)
                if res:
                    yield self._get_node_res(node, res)
            if id(node) not in discovered:  # pragma: no cover
                discovered.add(id(node))
                res_parts.extend([res] * (len(node) - 1))
                for key in sorted(
                    node.keys(),
                    key=lambda k: self._trie_type() if k is None else self._get_char(k),
                ):
                    visited.append((key, node[key]))

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

    def remove(self, string):
        node = self.root
        parents = list()
        for i in range(len(string) + 1):
            if i < len(string):
                key = string[i]
                parents.append((key, node, node.state))
                node = node.get_child(key)
                if node is None:
                    # string not in trie
                    return
            elif node.has_child(self._end_marker):
                node.remove_child(self._end_marker)
            else:
                # string not in trie
                return
        while parents:
            key, node, child_state = parents.pop()
            if not node.get_child(key, child_state):
                node.remove_child(key)


class StringTrie(BaseTrie):
    pass


class BytesTrie(BaseTrie):
    _trie_type = bytes

    def _get_char(self, char):
        if isinstance(char, self._trie_type):
            return char
        else:
            return self._trie_type([char])


class CountingBaseTrie(BaseTrie):
    _trie_node_class = CountingTrieNode

    def _get_node_res(self, node, res):
        return node.count, res


class CountingStringTrie(StringTrie, CountingBaseTrie):
    pass


class CountingBytesTrie(BytesTrie, CountingBaseTrie):
    pass
