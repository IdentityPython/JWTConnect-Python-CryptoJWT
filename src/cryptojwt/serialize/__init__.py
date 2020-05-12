
class SimpleList():
    def __init__(self, value=None):
        if value is None:
            self.db = []
        else:
            self.set(value)

    def __len__(self):
        return len(self.db)

    def __contains__(self, item):
        return item in self.db

    def __del__(self):
        del self.db

    def __iter__(self):
        for i in self.db:
            yield i

    def __str__(self):
        return str(self.db)

    def append(self, item):
        self.db.append(item)

    def extend(self, items):
        self.db.extend(items)

    def remove(self, item):
        self.db.remove(item)

    def get(self):
        return self.db

    def set(self, value):
        if isinstance(value, list):
            self.db = value
        else:
            raise ValueError("Wrong value type")

    def copy(self):
        return self.db[:]

    def close(self):
        return
