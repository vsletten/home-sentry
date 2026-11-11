"""Reply shapes observed from glm-5.3 on Ollama Cloud (2026-11-10), synthetic content."""

from homesentry import agent
from homesentry.store import Store


def test_double_encoded_answer_and_stringified_followups():
    raw = {
        "answer": '"**No**: nothing was reachable.\\n\\nTwo caveats, [D4]."',
        "followups": "['Can you test UDP?', 'How do I delete the forward on [D4]?']",
    }
    r = agent.normalize_reply(raw)
    assert r["answer"] == "**No**: nothing was reachable.\n\nTwo caveats, [D4]."
    assert r["followups"] == ["Can you test UDP?", "How do I delete the forward on [D4]?"]


def test_other_shapes():
    n = agent.normalize_reply
    assert n({"answer": "plain", "followups": ["a"]}) == {"answer": "plain", "followups": ["a"]}
    assert n({"answer": {"text": "nested"}})["answer"] == "nested"
    assert n({"answer": ["p1", "p2"]})["answer"] == "p1\n\np2"
    assert n({"reply": "wrong key but real text"})["answer"] == "wrong key but real text"
    assert (
        n('{"answer": "whole reply encoded", "followups": []}')["answer"] == "whole reply encoded"
    )
    assert n({"answer": "", "followups": "just one"}) == {"answer": "", "followups": ["just one"]}
    assert n(None) == {"answer": "", "followups": []}
    assert n({"answer": "__import__('os').system('x')"})["answer"].startswith("__import__")
    assert n({"followups": ["a", "b", "c", "d", " "]})["followups"] == ["a", "b", "c"]


def test_empty_answer_is_retried_once(tmp_path):
    st = Store(tmp_path / "inventory.db")

    class Flaky:
        calls = 0

        def chat_json(self, m):
            self.calls += 1
            return {"answer": "" if self.calls == 1 else "second try", "followups": []}

    llm = Flaky()
    assert agent.ask(st, llm, "hi")["answer"] == "second try" and llm.calls == 2

    class Dead:
        def chat_json(self, m):
            return {"answer": ""}

    assert agent.ask(st, Dead(), "hi")["answer"].startswith("(no answer")
