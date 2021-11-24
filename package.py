import json

class Package:
    def __init__(self, name, version, severity, advisory) -> None:
        self.name = name
        self.version = version
        self.severity = severity
        self.advisory = advisory

    # https://gist.github.com/changsin/f09d0379b857d85560f753aafed04858#file-label_class_1-py
    def __iter__(self):
        yield from {
            "name": self.name,
            "version": self.version,
            "severity": self.severity,
            "advisory": self.advisory,
        }.items()

    def __str__(self):
        return json.dumps(dict(self), ensure_ascii=False)

    def __repr__(self):
        return self.__str__()

    