from agents.basic_agent import BasicAgent


class EchoAgent(BasicAgent):
    def __init__(self):
        self.name = "Echo"
        self.metadata = {
            "name": self.name,
            "description": "Repeats the text back, upper-cased.",
            "parameters": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        }
        super().__init__(name=self.name, metadata=self.metadata)

    def perform(self, text="", **kwargs):
        return text.upper()


class BoomAgent(BasicAgent):
    def __init__(self):
        self.name = "Boom"
        self.metadata = {
            "name": self.name,
            "description": "Always fails.",
            "parameters": {"type": "object", "properties": {}},
        }
        super().__init__(name=self.name, metadata=self.metadata)

    def perform(self, **kwargs):
        raise ValueError("it blew up")


class WordStatsAgent(BasicAgent):
    def __init__(self):
        self.name = "WordStats"
        self.metadata = {
            "name": self.name,
            "description": "Counts words and characters.",
            "parameters": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        }
        super().__init__(name=self.name, metadata=self.metadata)

    def perform(self, text="", **kwargs):
        return f"words={len(text.split())} characters={len(text)}"
