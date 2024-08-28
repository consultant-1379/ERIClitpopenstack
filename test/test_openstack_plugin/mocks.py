import os
import mock
from litp.core.plugin import Plugin


class DummyPlugin(Plugin):

    @staticmethod
    def callback_method():
        pass


class State(object):
    INITIAL = 0
    APPLIED = 1
    UPDATED = 2
    FOR_REMOVAL = 3


def mock_model_item(item_id="", item_type_id="", state=State.INITIAL,
                    autospec=False, iscollection=False, collections=None, **kwargs):
    spec = ['get_vpath', 'is_updated', 'is_applied', 'is_for_removal',
            'is_initial', 'query_by_vpath', 'get_parent', 'query', 'properties']
    if autospec:
        item = _mock_model_item()
    else:
        item = _mock_model_item(spec)
    item.properties = {}
    for k, v in kwargs.iteritems():
        item.add_property(k, v)
    item.state = state
    item.item_id = item_id
    item.item_type_id = item_type_id
    item.get_vpath.side_effect = item._get_vpath
    item.is_updated.side_effect = item._is_updated
    item.is_applied.side_effect = item._is_applied
    item.is_initial.side_effect = item._is_initial
    item.is_for_removal.side_effect = item._is_for_removal
    item.query_by_vpath = item._query_by_vpath
    item.query = item._query
    item.get_parent = item._get_parent
    item.get_parent = item._get_parent
    item._parent = None
    item._iscollection = iscollection
    item._children = []
    item._collections = []
    if collections:
        for collection in collections:
            item.add_collection(collection)
    return item


class _mock_model_item(mock.MagicMock):

    def add_property(self, key, value):
        self.properties[key] = value
        setattr(self, key, value)

    def _get_vpath(self):
        if self._parent:
            return os.path.join(self._parent.get_vpath(), self.item_id)
        else:
            return "/"

    def _get_parent(self):
        return self._parent

    def _is_updated(self):
        return self._state_is(State.UPDATED)

    def _is_initial(self):
        return self._state_is(State.INITIAL)

    def _is_applied(self):
        return self._state_is(State.APPLIED)

    def _is_for_removal(self):
        return self._state_is(State.FOR_REMOVAL)

    def _state_is(self, state):
        return state == self.state

    def _get_root(self):
        item = self
        while(item._get_vpath() != "/"):
            item = item.get_parent()
        return item

    def _query_by_vpath(self, vpath):
        return self._get_root()

    def _check_item(self, item, item_type, **kwargs):
        if item.item_type_id == item_type:
            for k, v in kwargs.iteritems():
                if getattr(item, k, None) != v:
                    return False
            return True
        return False

    def _query(self, item_type, **kwargs):
        items = []
        for child in self._children:
            item = getattr(self, child)
            if isinstance(item, list):
                for child in item:
                    if self._check_item(child, item_type, **kwargs):
                        items.append(child)
                    items.extend(child.query(item_type, **kwargs))
            else:
                if self._check_item(item, item_type, **kwargs):
                    items.append(item)
                items.extend(item.query(item_type, **kwargs))
        return items

    def has_initial_dependencies(self):
        return self._check_has_dependencies(State.INITIAL)

    def has_removed_dependencies(self):
        return self._check_has_dependencies(State.FOR_REMOVAL)

    def has_updated_dependencies(self):
        return self._check_has_dependencies(State.UPDATED)

    def _check_has_dependencies(self, state):
        for child in self._children:
            item = getattr(self, child)
            if isinstance(item, list):
                for child in item:
                    if child.state == state:
                        return True
                    return child._check_has_dependencies(state)
            else:
                if item.state == state:
                    return True
                else:
                    return item._check_has_dependencies(state)
        return False

    def set_all_applied(self):
        self._set_state_for_all(State.APPLIED)

    def set_all_for_removal(self):
        self._set_state_for_all(State.FOR_REMOVAL)

    def set_all_updated(self):
        self._set_state_for_all(State.UPDATED)

    def _set_state_for_all(self, state):
        self.state = state
        for child in self._children:
            item = getattr(self, child)
            if isinstance(item, list):
                for child in item:
                    child._set_state_for_all(state)
            else:
                item._set_state_for_all(state)

    def set_applied(self):
        self.state = State.APPLIED

    def set_updated(self):
        self.state = State.UPDATED

    def set_initial(self):
        self.state = State.INITIAL

    def set_for_removal(self):
        self.state = State.FOR_REMOVAL

    def add_child_to_collection(self, child, collection):
        c = mock_model_item(collection, iscollection=True)
        if not hasattr(self, collection):
            setattr(self, collection, c)
        else:
            c = getattr(self, collection)
        c.add_child(child)
        self.add_child(c)

    def add_collection(self, collection):
        c = mock_model_item(collection, iscollection=True)
        self.add_child(c)

    def add_child(self, child):
        child._parent = self
        self._children.append(child.item_id)
        setattr(self, child.item_id, child)

    def __str__(self):
        return self._get_vpath()

    def __getitem__(self, key):
        if self._iscollection:
            return getattr(self, self._children[key])

    def __len__(self):
        return len(self._children)


def mock_node(number=1, interfaces=0):
    name = "node{0}".format(number)
    node = mock_model_item("/{0}".format(name), name)
    return node
